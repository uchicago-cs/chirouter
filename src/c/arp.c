/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the code that manages the ARP cache and
 *  the list of pending ARP requests.
 *
 *  Most importantly, this module defines a function chirouter_arp_process that
 *  is run as a separate thread, and which will wake up every second to purge
 *  stale entries in the ARP cache (entries that are more than 15 seconds old)
 *  and to traverse the list of pending ARP requests. For each pending request
 *  in the list, it will call chirouter_arp_process_pending_req, which must
 *  either re-send the pending ARP request or cancel the request and send ICMP
 *  Host Unreachable messages in reply to all the withheld frames.
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

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <stdbool.h>

#include "arp.h"
#include "chirouter.h"
#include "server.h"
#include "utils.h"
#include "utlist.h"

#define ARP_REQ_KEEP (0)
#define ARP_REQ_REMOVE (1)

/* How often (in seconds) the ARP thread purges the ARP cache and
 * processes the pending ARP requests */
#define ARP_THREAD_INTERVAL (1)

/*
 * chirouter_arp_process_pending_req - Process a single pending ARP request
 *
 * Given a pending ARP request, this function will do the following:
 *
 * - If the request has been sent less than five times, re-send the request
 *   (and update the chirouter_pending_arp_req_t struct to reflect
 *   the number of times the request has been sent) and return ARP_REQ_KEEP
 * - If the request has been sent five times, send an ICMP Host Unreachable
 *   reply for each of the withheld frames and return ARP_REQ_REMOVE
 *
 * ctx: Router context
 *
 * pending_req: Pending ARP request
 *
 * Returns:
 *  - ARP_REQ_KEEP if the ARP request should stay in the pending ARP request
 *  list.
 *  - ARP_REQ_REMOVE if the request should be removed from the list.
 */
static int chirouter_arp_process_pending_req(chirouter_ctx_t *ctx,
        chirouter_pending_arp_req_t *pending_req)
{
    /* Your code goes here */

    /* You will be able to write the rest of the code while having
     * this function always return ARP_REQ_KEEP, but make sure you
     * return the correct return value when you implement this function */

    return ARP_REQ_KEEP;
}


/***** DO NOT MODIFY THE CODE BELOW *****/


/* See arp.h */
time_t chirouter_arp_time_now(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec;
}


/* See arp.h */
chirouter_arpcache_entry_t* chirouter_arp_cache_lookup(chirouter_ctx_t *ctx,
        const struct in_addr *ip)
{
    for (unsigned int i = 0; i < ARPCACHE_SIZE; i++)
    {
        if (ctx->arpcache[i].valid && ctx->arpcache[i].ip.s_addr == ip->s_addr)
        {
            return &ctx->arpcache[i];
        }
    }

    return NULL;
}


/* See arp.h */
int chirouter_arp_cache_add(chirouter_ctx_t *ctx, const struct in_addr *ip,
                            const uint8_t *mac)
{
    chirouter_arpcache_entry_t *entry = chirouter_arp_cache_lookup(ctx, ip);

    if (entry != NULL)
    {
        memcpy(entry->mac, mac, ETHER_ADDR_LEN);
        entry->time_added = chirouter_arp_time_now();

        return CHIROUTER_OK;
    }

    for (unsigned int i = 0; i < ARPCACHE_SIZE; i++)
    {
        if (!ctx->arpcache[i].valid)
        {
            ctx->arpcache[i].valid = true;
            memcpy(&ctx->arpcache[i].ip, ip, sizeof(struct in_addr));
            memcpy(ctx->arpcache[i].mac, mac, ETHER_ADDR_LEN);
            ctx->arpcache[i].time_added = chirouter_arp_time_now();

            return CHIROUTER_OK;
        }
    }

    return CHIROUTER_ERROR;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_lookup(
    chirouter_ctx_t *ctx, const struct in_addr *ip)
{
    chirouter_pending_arp_req_t *elt;
    DL_FOREACH(ctx->pending_arp_reqs, elt)
    {
        if (elt->ip.s_addr == ip->s_addr)
        {
            return elt;
        }
    }

    return NULL;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_add(chirouter_ctx_t *ctx,
        const struct in_addr *ip, chirouter_interface_t *iface)
{
    chirouter_pending_arp_req_t *pending_req = xcalloc(1,
            sizeof(chirouter_pending_arp_req_t));

    memcpy(&pending_req->ip, ip, sizeof(struct in_addr));
    pending_req->times_sent = 0;
    pending_req->last_sent = chirouter_arp_time_now();
    pending_req->out_interface = iface;
    pending_req->withheld_frames = NULL;

    DL_APPEND(ctx->pending_arp_reqs, pending_req);

    return pending_req;
}


/* See arp.h */
int chirouter_arp_pending_req_add_frame(
    chirouter_ctx_t *ctx,
    chirouter_pending_arp_req_t *pending_req,
    const ethernet_frame_t *frame)
{
    withheld_frame_t *withheld = xcalloc(1, sizeof(withheld_frame_t));

    withheld->frame = xcalloc(1, sizeof(ethernet_frame_t));
    withheld->frame->raw = xmalloc(frame->length);
    memcpy(withheld->frame->raw, frame->raw, frame->length);
    withheld->frame->length = frame->length;
    withheld->frame->in_interface = frame->in_interface;

    DL_APPEND(pending_req->withheld_frames, withheld);

    return CHIROUTER_OK;
}


/* See arp.h */
int chirouter_arp_pending_req_free_frames(chirouter_pending_arp_req_t
        *pending_req)
{
    withheld_frame_t *elt, *tmp;

    DL_FOREACH_SAFE(pending_req->withheld_frames, elt, tmp)
    {
        free(elt->frame->raw);
        free(elt->frame);
        DL_DELETE(pending_req->withheld_frames, elt);
        free(elt);
    }

    return CHIROUTER_OK;
}


/* See arp.h */
void* chirouter_arp_process(void *args)
{
    chirouter_ctx_t *ctx = (chirouter_ctx_t *) args;

    pthread_mutex_lock(&(ctx->lock_arp));

    while (!ctx->arp_thread_stop)
    {
        /* Purge the cache */
        time_t curtime = chirouter_arp_time_now();
        for (unsigned int i = 0; i < ARPCACHE_SIZE; i++)
        {
            chirouter_arpcache_entry_t *cache_entry = &ctx->arpcache[i];
            double entry_age = difftime(curtime, cache_entry->time_added);

            if ((cache_entry->valid) && (entry_age > ARPCACHE_ENTRY_TIMEOUT))
            {
                cache_entry->valid = false;
            }
        }

        /* Process pending ARP requests */
        if (ctx->pending_arp_reqs != NULL)
        {
            chirouter_pending_arp_req_t *elt, *tmp;

            DL_FOREACH_SAFE(ctx->pending_arp_reqs, elt, tmp)
            {
                int rc = chirouter_arp_process_pending_req(ctx, elt);

                if (rc == ARP_REQ_REMOVE)
                {
                    chirouter_arp_pending_req_free_frames(elt);
                    DL_DELETE(ctx->pending_arp_reqs, elt);
                    free(elt);
                }
            }
        }

        /* Wait until it's time to run again (or until we're told to stop).
         * pthread_cond_timedwait releases lock_arp while waiting, and can
         * return early ("spurious wakeups"), so we wait in a loop. Note that
         * the deadline must use CLOCK_REALTIME (the clock that condition
         * variables use by default) */
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += ARP_THREAD_INTERVAL;

        int rc = 0;
        while (!ctx->arp_thread_stop && rc != ETIMEDOUT)
            rc = pthread_cond_timedwait(&ctx->arp_thread_cond,
                                        &ctx->lock_arp, &deadline);
    }

    pthread_mutex_unlock(&(ctx->lock_arp));

    return NULL;
}
