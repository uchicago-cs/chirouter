/*
 *  chirouter - A simple, testable IP router
 *
 *  main() function for the router
 *
 *  The chirouter executable accepts three command-line arguments:
 *
 *  -r RTABLE: The routing table for the router
 *  -s POX_HOST: The host running the POX controller (default: localhost)
 *  -p POX_PORT: The port the POX controller is listening on
 *  -v: Be verbose. Can be repeated up to three times for extra verbosity.
 *
 *  The main() function takes care of processing these command-line
 *  arguments and launching the router.
 *
 */

/*
 * This project is based on the Simple Router assignment included in the
 * Mininet project (https://github.com/mininet/mininet/wiki/Simple-Router) which,
 * in turn, is based on a programming assignment developed at Stanford
 * (http://www.scs.stanford.edu/09au-cs144/lab/router.html)
 *
 * While most of the code for chirouter has been written from scratch, some
 * of the original Stanford code is still present in some places and, whenever
 * possible, we have tried to provide the exact attribution for such code.
 * Any omissions are not intentional and will be gladly corrected if
 * you contact us at borja@cs.uchicago.edu
 */

/*
 *  Copyright (c) 2016, The University of Chicago
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
#include <signal.h>
#include <arpa/inet.h>

#include <getopt.h>

#include "chirouter.h"
#include "server.h"
#include "arp.h"
#include "log.h"
#include "pcap.h"

#define USAGE "Usage: chirouter [-p PORT] [-c CAP_FILE] [(-v|-vv|-vvv)]\n"

int main(int argc, char *argv[])
{
    int rc;
    server_ctx_t *ctx;
    sigset_t new;
    int opt;
    char *port = "23300";
    /* char *cap_file = NULL; */
    int verbosity = 0;
    bool debug = false;

    /* Stop SIGPIPE from messing with our sockets */
    sigemptyset (&new);
    sigaddset(&new, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &new, NULL) != 0)
    {
        perror("Unable to mask SIGPIPE");
        exit(-1);
    }

    /* Process command-line arguments */
    while ((opt = getopt(argc, argv, "p:c:vdh")) != -1)
        switch (opt)
        {
        case 'p':
            port = strdup(optarg);
            break;
        /*case 'c':
            cap_file = strdup(optarg);
            break;*/
        case 'v':
            verbosity++;
            break;
        case 'd':
            debug = true;
            break;
        case 'h':
            printf(USAGE);
            exit(0);
        default:
            fprintf(stderr, USAGE);
            fprintf(stderr, "ERROR: Unknown option -%c\n", opt);
            return EXIT_FAILURE;
        }

    /* Set logging level based on verbosity */
    switch(verbosity)
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
    case 3:
        chirouter_setloglevel(TRACE);
        break;
    default:
        chirouter_setloglevel(TRACE);
        break;
    }

    /* Initialize server context */
    rc = chirouter_server_ctx_init(&ctx);
    if(rc)
    {
        perror("ERROR: Could not allocate memory for server context");
        return EXIT_FAILURE;
    }

    ctx->debug = debug;
    rc = chirouter_server_setup(ctx, port);
    if(rc)
    {
        perror("ERROR: Could not start chirouter server.");
        return EXIT_FAILURE;
    }

    rc = chirouter_server_run(ctx);

    chirouter_server_ctx_destroy(ctx);

    return EXIT_SUCCESS;
}





