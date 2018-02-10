/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains the code that manages the ARP cache and
 *  the list of pending ARP requests.
 *
 *  Most importantly, this module defines a function chirouter_arp_process
 *  that is run as a separate thread, and which will wake up every second
 *  to purge stale entries in the ARP cache (entries that are more than 15 seconds
 *  old) and to traverse the list of pending ARP requests. For each pending
 *  request in the list, it will call chirouter_arp_process_pending_req,
 *  which must either re-send the pending ARP request or cancel the
 *  request and send ICMP Host Unreachable messages in reply to all
 *  the withheld frames.
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
#include "utils.h"

#define ARP_REQ_KEEP (0)
#define ARP_REQ_REMOVE (1)


/*
 * chirouter_arp_process_pending_req - Process a single pending ARP request
 *
 * Given a pending ARP request, this function will do the following:
 *
 * - If the request has been sent less than five times, re-send the request
 *   (and update the the chirouter_pending_arp_req_t struct to reflect
 *   the number of times the request has been sent) and return ARP_REQ_KEEP
 * - If the request has been sent five times, send an ICMP Host Unreachable
 *   reply for each of the withheld frames and return ARP_REQ_REMOVE
 *
 * ctx: Router context
 *
 * pending_req: Pending ARP request
 *
 * Returns:
 *  - ARP_REQ_KEEP if the ARP request should stay in the pending ARP request list.
 *  - ARP_REQ_REMOVE if the request should be removed from the list.
 */
int chirouter_arp_process_pending_req(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req)
{
    /* Your code goes here */

    /* You will be able to write the rest of the code while having
     * this function always return ARP_REQ_KEEP, but make sure you
     * return the correct return value when you implement this function */

    return ARP_REQ_KEEP;
}
      


/***** DO NOT MODIFY THE CODE BELOW *****/


/* See arp.h */
chirouter_arpcache_entry_t* chirouter_arp_cache_lookup(chirouter_ctx_t *ctx, struct in_addr *ip)
{
    for(int i=0; i < ARPCACHE_SIZE; i++)
    {
        if(ctx->arpcache[i].valid && ctx->arpcache[i].ip.s_addr == ip->s_addr)
        {
            return &ctx->arpcache[i];
        }
    }

    return NULL;
}


/* See arp.h */
int chirouter_arp_cache_add(chirouter_ctx_t *ctx, struct in_addr *ip, uint8_t *mac)
{
    for(int i=0; i < ARPCACHE_SIZE; i++)
    {
        if(!ctx->arpcache[i].valid)
        {
            ctx->arpcache[i].valid = true;
            memcpy(&ctx->arpcache[i].ip, ip, sizeof(struct in_addr));
            memcpy(ctx->arpcache[i].mac, mac, ETHER_ADDR_LEN);
            ctx->arpcache[i].time_added = time(NULL);

            return 0;
        }
    }

    return 1;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_lookup(chirouter_ctx_t *ctx, struct in_addr *ip)
{
    list_iterator_start(ctx->pending_arp_reqs);
    while(list_iterator_hasnext(ctx->pending_arp_reqs))
    {
        chirouter_pending_arp_req_t *pending_req = list_iterator_next(ctx->pending_arp_reqs);
        if(pending_req->ip.s_addr == ip->s_addr)
        {
            list_iterator_stop(ctx->pending_arp_reqs);
            return pending_req;
        }
    }
    list_iterator_stop(ctx->pending_arp_reqs);

    return NULL;
}


/* See arp.h */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_add(chirouter_ctx_t *ctx, struct in_addr *ip, chirouter_interface_t *iface)
{
    chirouter_pending_arp_req_t *pending_req = malloc(sizeof(chirouter_pending_arp_req_t));

    memcpy(&pending_req->ip, ip, sizeof(struct in_addr));
    pending_req->times_sent = 0;
    pending_req->last_sent = time(NULL);
    pending_req->out_interface = iface;

    list_init(&pending_req->withheld_frames);

    list_append(ctx->pending_arp_reqs, pending_req);

    return pending_req;
}


/* See arp.h */
int chirouter_arp_pending_req_add_frame(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req, ethernet_frame_t *frame)
{
    ethernet_frame_t *frame_copy = malloc(sizeof(ethernet_frame_t));

    frame_copy->raw = malloc(frame->length);
    memcpy(frame_copy->raw, frame->raw, frame->length);
    frame_copy->length = frame->length;
    frame_copy->in_interface = frame->in_interface;

    list_append(&pending_req->withheld_frames, frame_copy);

    return 0;
}


/* See arp.h */
int chirouter_arp_free_pending_req(chirouter_pending_arp_req_t *pending_req)
{
    list_iterator_start(&pending_req->withheld_frames);
    while (list_iterator_hasnext(&pending_req->withheld_frames))
    {
        ethernet_frame_t *frame = (ethernet_frame_t *) list_iterator_next(&pending_req->withheld_frames);
        free(frame->raw);
        free(frame);
    }
    list_iterator_stop(&pending_req->withheld_frames);

    list_destroy(&pending_req->withheld_frames);
    
    return 0;
}


/* See arp.h */
void* chirouter_arp_process(void *args)
{
    chirouter_ctx_t *ctx = (chirouter_ctx_t *) args;

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(ctx->lock_arp));

        /* Purge the cache */
        time_t curtime = time(NULL);
        for(int i = 0; i < ARPCACHE_SIZE; i++)
        {
            chirouter_arpcache_entry_t *cache_entry = &ctx->arpcache[i];
            double entry_age = difftime(curtime, cache_entry->time_added);

            if ((cache_entry->valid) && (entry_age > ARPCACHE_ENTRY_TIMEOUT)) {
                cache_entry->valid = false;
            }
        }

        /* Process pending ARP requests */
        if (list_size(ctx->pending_arp_reqs) > 0)
        {
            /*  Unfortunately, simclist doesn't allow entries to be deleted
             *  while iterating over the list, so instead we create
             *  a new list with the pending requests we want to keep. */
            list_t *new_list = malloc(sizeof(list_t));
            list_init(new_list);
            list_iterator_start(ctx->pending_arp_reqs);
            while (list_iterator_hasnext(ctx->pending_arp_reqs))
            {
                int rc;
                chirouter_pending_arp_req_t *pending_req;

                pending_req = (chirouter_pending_arp_req_t *) list_iterator_next(ctx->pending_arp_reqs);
                rc = chirouter_arp_process_pending_req(ctx, pending_req);

                if(rc == ARP_REQ_KEEP)
                {
                    rc = list_append(new_list, pending_req);
                }
                else
                {
                    chirouter_arp_free_pending_req(pending_req);
                }
            }
            list_iterator_stop(ctx->pending_arp_reqs);

            /* Swap list */
            list_destroy(ctx->pending_arp_reqs);
            free(ctx->pending_arp_reqs);
            ctx->pending_arp_reqs = new_list;
       }

        pthread_mutex_unlock(&(ctx->lock_arp));
    }

    return NULL;
}
