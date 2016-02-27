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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "chirouter.h"
#include "log.h"



int chirouter_ctx_init(chirouter_ctx_t **ctx)
{
    /* Initialize all pointers and sizes to zero */
    /* This also initializes the ARP cache to all invalid entries */
    *ctx = calloc(1, sizeof(chirouter_ctx_t));

    if(*ctx == NULL)
        return 1;

    (*ctx)->pox_socket = -1;

    pthread_mutex_init(&(*ctx)->lock_arp, NULL);
    (*ctx)->pending_arp_reqs = malloc(sizeof(list_t));
    list_init((*ctx)->pending_arp_reqs);

    return 0;
}

/* Adapted from Simple Router's sr_load_rt() in sr_rc.c (Author: casado@stanford.edu) */
int chirouter_ctx_load_rtable(chirouter_ctx_t *ctx, const char* rtable_filename)
{
    FILE* fp;
    char line[BUFSIZ];
    char dest[32];
    char gw[32];
    char mask[32];
    char iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;

    fp = fopen(rtable_filename,"r");

    while(fgets(line, BUFSIZ, fp) != 0)
    {
        sscanf(line, "%s %s %s %s", dest, gw, mask, iface);

        if(inet_aton(dest, &dest_addr) == 0)
        {
            chilog(CRITICAL, "Error loading routing table, cannot convert %s to valid IP", dest);
            return -1;
        }

        if(inet_aton(gw, &gw_addr) == 0)
        {
            chilog(CRITICAL, "Error loading routing table, cannot convert %s to valid IP", gw);
            return -1;
        }

        if(inet_aton(mask, &mask_addr) == 0)
        {
            chilog(CRITICAL, "Error loading routing table, cannot convert %s to valid IP", mask);
            return -1;
        }

        /* Add entry to routing table */
        int i = ctx->num_rtable_entries;
        ctx->routing_table = realloc(ctx->routing_table, sizeof(chirouter_rtable_entry_t) * (i + 1));
        if(ctx->routing_table == NULL)
        {
            chilog(CRITICAL, "Could not allocate memory for routing table");
            return -1;
        }

        chirouter_rtable_entry_t *entry = &ctx->routing_table[i];
        entry->dest = dest_addr;
        entry->gw   = gw_addr;
        entry->mask = mask_addr;
        strncpy(entry->interface_name, iface, MAX_IFACE_NAMELEN);
        entry->interface = NULL;

        ctx->num_rtable_entries++;
    }

    return 0;
}

int chirouter_ctx_add_iface(chirouter_ctx_t *ctx, const char* iface_name, uint8_t mac[ETHER_ADDR_LEN], struct in_addr *ip)
{
    /* Add entry to interface table */
    int i = ctx->num_interfaces;
    ctx->interfaces = realloc(ctx->interfaces, sizeof(chirouter_interface_t) * (i + 1));
    if(ctx->interfaces == NULL)
    {
        chilog(CRITICAL, "Could not allocate memory for routing table");
        return -1;
    }

    chirouter_interface_t *entry = &ctx->interfaces[i];
    strncpy(entry->name, iface_name, MAX_IFACE_NAMELEN);
    memcpy(entry->mac, mac, ETHER_ADDR_LEN);
    memcpy(&entry->ip, ip, sizeof(struct in_addr));

    ctx->num_interfaces++;

    return 0;
}


/* Adapted from Simple Router's sr_print_routing_table() in sr_rc.c (Author: casado@stanford.edu) */
void chirouter_ctx_log_rtable(chirouter_ctx_t *ctx, loglevel_t loglevel)
{
    if(ctx->num_rtable_entries == 0)
    {
        chilog(loglevel, "Routing table is empty.");
        return;
    }

    chilog(loglevel, "%-16s%-16s%-16s%-16s", "Destination", "Gateway", "Mask", "Iface");

    for(int i=0; i < ctx->num_rtable_entries; i++)
    {
        chirouter_rtable_entry_t *entry = &ctx->routing_table[i];

        char* dest = strdup(inet_ntoa(entry->dest));
        char* gw = strdup(inet_ntoa(entry->gw));
        char* mask = strdup(inet_ntoa(entry->mask));

        chilog(loglevel, "%-16s%-16s%-16s%-16s", dest, gw, mask, entry->interface_name);

        free(dest);
        free(gw);
        free(mask);
    }
}


int chirouter_ctx_destroy(chirouter_ctx_t *ctx)
{
    return 0;
}
