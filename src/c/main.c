/*
 *  chirouter - A simple, testable IP router
 *
 *  main() function for the router
 *
 *  The chirouter executable accepts three command-line arguments:
 *
 *  -p PORT: Port on which chirouter will listen (default: 23320)
 *  -c FILE: If specified, will produce a pcapng capture file with all
 *           the Ethernet frames received/sent by the routers.
 *  -v: Be verbose. Can be repeated up to three times for extra verbosity.
 *
 *  The main() function takes care of processing these command-line
 *  arguments and launching the router processing code.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the Mininet
 * project (https://github.com/mininet/mininet/wiki/Simple-Router) which, in
 * turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016-2018, The University of Chicago
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of The University of Chicago nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>

#include <getopt.h>

#include "chirouter.h"
#include "server.h"
#include "arp.h"
#include "log.h"
#include "pcap.h"

#define USAGE "Usage: chirouter [-p PORT] [-c CAP_FILE] [(-q|-v|-vv|-vvv)]\n"


/* Arguments to the signal-handling thread */
typedef struct signal_thread_args
{
    /* Server context (the server will be stopped when a signal arrives) */
    server_ctx_t *ctx;

    /* Signals to wait for */
    sigset_t signals;
} signal_thread_args_t;


/*
 * signal_thread_func - Signal-handling thread
 *
 * SIGINT and SIGTERM are blocked in all threads, and are handled by
 * this thread, which stops the server (so that chirouter shuts down
 * the routers and exits normally, closing the capture file). Since
 * this is a regular thread, and not a signal handler, it is not
 * limited to async-signal-safe functions.
 *
 * args: Pointer to a signal_thread_args_t struct
 *
 * Returns: NULL. If sigwait fails, the thread exits without stopping
 *          the server.
 */
static void *signal_thread_func(void *args)
{
    signal_thread_args_t *sargs = (signal_thread_args_t *) args;
    int sig;

    if (sigwait(&sargs->signals, &sig) == 0)
    {
        fprintf(stderr, "Exiting chirouter...\n");
        chirouter_server_stop(sargs->ctx);
    }

    return NULL;
}


/*
 * main - Runs chirouter
 *
 * Processes the command-line arguments (see USAGE), sets up the
 * server, and runs it until it is stopped (with SIGINT or SIGTERM)
 * or a critical error happens.
 *
 * argc, argv: Command-line arguments
 *
 * Returns: EXIT_SUCCESS if chirouter was stopped normally, EXIT_FAILURE
 *          if the command-line arguments are incorrect or an error happens.
 */
int main(int argc, char *argv[])
{
    int rc;
    int exit_status = EXIT_FAILURE;
    char errbuf[STRERROR_BUF_LEN];

    server_ctx_t *ctx;
    sigset_t new;
    pthread_t signal_thread;
    signal_thread_args_t signal_thread_args;
    int opt;
    const char *port = "23320";
    const char *cap_file = NULL;
    int verbosity = 0;
    bool quiet = false;

    /* Stop SIGPIPE from messing with our sockets */
    sigemptyset(&new);
    sigaddset(&new, SIGPIPE);
    /* pthread_sigmask returns an error code (instead of setting errno) */
    if ((rc = pthread_sigmask(SIG_BLOCK, &new, NULL)) != 0)
    {
        chilog(CRITICAL, "Unable to mask SIGPIPE: %s",
               chirouter_strerror(rc, errbuf, sizeof(errbuf)));
        exit(EXIT_FAILURE);
    }

    /* Block SIGINT and SIGTERM, so they are handled by the signal-handling
     * thread (this must be done before any threads are created, since
     * threads inherit the signal mask of the thread that creates them) */
    sigemptyset(&signal_thread_args.signals);
    sigaddset(&signal_thread_args.signals, SIGINT);
    sigaddset(&signal_thread_args.signals, SIGTERM);
    if ((rc = pthread_sigmask(SIG_BLOCK, &signal_thread_args.signals,
                              NULL)) != 0)
    {
        chilog(CRITICAL, "Unable to mask SIGINT and SIGTERM: %s",
               chirouter_strerror(rc, errbuf, sizeof(errbuf)));
        exit(EXIT_FAILURE);
    }

    /* Process command-line arguments */
    while ((opt = getopt(argc, argv, "p:c:vqh")) != -1)
        switch (opt)
        {
        case 'p':
            port = optarg;
            break;
        case 'c':
            cap_file = optarg;
            break;
        case 'v':
            verbosity++;
            break;
        case 'q':
            quiet = true;
            break;
        case 'h':
            printf(USAGE);
            exit(EXIT_SUCCESS);
        default:
            fprintf(stderr, USAGE);
            fprintf(stderr, "ERROR: Unknown option -%c\n", opt);
            return EXIT_FAILURE;
        }

    if (quiet && verbosity > 0)
    {
        fprintf(stderr, USAGE);
        fprintf(stderr, "ERROR: -q and -v cannot be used together\n");
        return EXIT_FAILURE;
    }

    /* Set logging level based on verbosity */
    if (quiet)
    {
        chirouter_setloglevel(QUIET);
    }
    else
    {
        switch (verbosity)
        {
        case 0:
            chirouter_setloglevel(ERROR);
            break;
        case 1:
            chirouter_setloglevel(INFO);
            break;
        case 2:
            chirouter_setloglevel(DEBUG);
            break;
        default:
            chirouter_setloglevel(TRACE);
            break;
        }
    }

    /* Initialize server context */
    rc = chirouter_server_ctx_init(&ctx);
    if (rc)
    {
        chilog(CRITICAL, "Could not allocate memory for server context");
        return EXIT_FAILURE;
    }

    /* Create capture file */
    if (cap_file)
    {
        ctx->pcap = fopen(cap_file, "w");

        if (!ctx->pcap)
        {
            chilog(CRITICAL, "Capture file %s could not be created: %s", cap_file,
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            goto cleanup;
        }
    }

    rc = chirouter_server_setup(ctx, port);
    if (rc)
    {
        chilog(CRITICAL, "Could not start chirouter server");
        goto cleanup;
    }

    signal_thread_args.ctx = ctx;
    if (pthread_create(&signal_thread, NULL, signal_thread_func,
                       &signal_thread_args) != 0)
    {
        chilog(CRITICAL, "Could not create signal-handling thread");
        goto cleanup;
    }

    rc = chirouter_server_run(ctx);

    /* The server may have stopped because of an error (and not because of
     * a signal), so the signal-handling thread may still be waiting. In either
     * case, we make sure it is done before freeing the server context. */
    pthread_cancel(signal_thread);
    pthread_join(signal_thread, NULL);

    if (rc == CHIROUTER_OK)
        exit_status = EXIT_SUCCESS;

cleanup:
    chirouter_server_ctx_destroy(ctx);

    if (ctx->pcap)
        fclose(ctx->pcap);
    free(ctx);

    return exit_status;
}


