/*
 *  chirouter - A simple, testable IP router
 *
 *  This module provides functions to manage the chirouter context.
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "chirouter.h"
#include "log.h"
#include "utlist.h"


/*
 * chirouter_ctx_init - Initializes a router context
 *
 * ctx: Router context
 *
 * Returns: 0 on success, -1 if an error happens.
 */
int chirouter_ctx_init(chirouter_ctx_t *ctx)
{
    pthread_mutex_init(&ctx->lock_arp, NULL);
    ctx->pending_arp_reqs = NULL;

    return 0;
}


/*
 * chirouter_ctx_log - Log contents of a router context
 *
 * ctx: Router context
 *
 * loglevel: Log level
 *
 * Returns: 0 on success, -1 if an error happens.
 */
void chirouter_ctx_log(chirouter_ctx_t *ctx, loglevel_t loglevel)
{
    chilog(loglevel, "ROUTER %s", ctx->name);
    chilog(loglevel, "");

    if(ctx->num_interfaces == 0)
    {
        chilog(loglevel, "Router has no interfaces");
    }
    else
    {
        for(int i=0; i < ctx->num_interfaces; i++)
        {
            chirouter_interface_t *iface = &ctx->interfaces[i];

            chilog(loglevel, "%s %02X:%02X:%02X:%02X:%02X:%02X %s",iface->name,
                             iface->mac[0], iface->mac[1], iface->mac[2],
                             iface->mac[3], iface->mac[4], iface->mac[5],
                             inet_ntoa(iface->ip));
        }
    }

    chilog(loglevel, "");

    /* Routing table logging code adapted from Simple Router's sr_print_routing_table()
     * in sr_rc.c (Author: casado@stanford.edu) */

    if(ctx->num_rtable_entries == 0)
    {
        chilog(loglevel, "Routing table is empty.");
    }
    else
    {
        chilog(loglevel, "%-16s%-16s%-16s%-16s", "Destination", "Gateway", "Mask", "Iface");

        for(int i=0; i < ctx->num_rtable_entries; i++)
        {
            chirouter_rtable_entry_t *entry = &ctx->routing_table[i];

            char* dest = strdup(inet_ntoa(entry->dest));
            char* gw = strdup(inet_ntoa(entry->gw));
            char* mask = strdup(inet_ntoa(entry->mask));

            chilog(loglevel, "%-16s%-16s%-16s%-16s", dest, gw, mask, entry->interface->name);

            free(dest);
            free(gw);
            free(mask);
        }
    }
}


/*
 * chirouter_ctx_destroy - Frees router resources
 *
 * ctx: Router context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_ctx_destroy(chirouter_ctx_t *ctx)
{
    pthread_mutex_destroy(&ctx->lock_arp);

    chirouter_pending_arp_req_t *pending_req, *tmp;
    DL_FOREACH_SAFE(ctx->pending_arp_reqs, pending_req, tmp)
    {
        DL_DELETE(ctx->pending_arp_reqs, pending_req);
    }
    free(ctx->pending_arp_reqs);

    return 0;
}
