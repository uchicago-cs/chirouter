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

#ifndef CHIROUTER_ARPCACHE_H
#define CHIROUTER_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "chirouter.h"


/*
 * chirouter_arp_cache_lookup - Look up an IP in the ARP cache
 *
 * Note: The lock_arp mutex in the router context must be locked before
 *       calling this function
 *
 * ctx: Router context
 *
 * ip: IP address being looked up.
 *
 * Returns: If the cache contains a valid entry for the IP address, returns
 *          a pointer to the chirouter_arpcache_entry_t struct corresponding to
 *          that entry in the cache.
 *          If no such entry exists, returns NULL.
 */
chirouter_arpcache_entry_t* chirouter_arp_cache_lookup(chirouter_ctx_t *ctx, struct in_addr *ip);


/*
 * chirouter_arp_cache_add - Add an entry to the ARP cache
 *
 * Note: The lock_arp mutex in the router context must be locked before
 *       calling this function
 *
 * ctx: Router context
 *
 * ip, mac: IP address (and MAC address corresponding to that IP address)
 *          to be added to the cache.
 *
 * Returns: 0 on success, 1 on error.
 */
int chirouter_arp_cache_add(chirouter_ctx_t *ctx, struct in_addr *ip, uint8_t *mac);


/*
 * chirouter_arp_pending_req_lookup - Look up a pending ARP request by IP
 *
 * Note: The lock_arp mutex in the router context must be locked before
 *       calling this function
 *
 * ctx: Router context
 *
 * ip: IP address of the pending ARP request.
 *
 * Returns: If the list of pending ARP requests contains a pending request for the IP address,
 *          returns a pointer to the chirouter_pending_arp_req_t struct corresponding to
 *          that pending request.
 *          If no such pending request exists, returns NULL.
 */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_lookup(chirouter_ctx_t *ctx, struct in_addr *ip);


/*
 * chirouter_arp_pending_req_add - Add a pending ARP request to the pending ARP request list
 *
 * Note: The lock_arp mutex in the router context must be locked before
 *       calling this function. This function also does not check whether
 *       a request for the provided IP already exists; you must use
 *       chirouter_arp_pending_req_lookup to verify that no such pending
 *       request exists before calling this function.
 *
 * ctx: Router context
 *
 * ip: IP address of the pending ARP request.
 *
 * iface: Router interface on which the ARP request was sent.
 *
 * Returns: A pointer to the pending request (a chirouter_pending_arp_req_t struct)
 *          that was added to the pending ARP request list.
 */
chirouter_pending_arp_req_t* chirouter_arp_pending_req_add(chirouter_ctx_t *ctx, struct in_addr *ip, chirouter_interface_t *iface);


/*
 * chirouter_arp_pending_req_add_frame - Add an Ethernet frame to a pending ARP request list
 *
 * Note: The lock_arp mutex in the router context must be locked before
 *       calling this function.
 *
 * ctx: Router context
 *
 * pending_req: Pending request that the frame should be added to.
 *
 * frame: Frame to be added. Note: This function will make a deep copy of the frame
 *        and will add that copy to the list of withheld frames.
 *
 * Returns: 0 on success, 1 on error.
 */
int chirouter_arp_pending_req_add_frame(chirouter_ctx_t *ctx, chirouter_pending_arp_req_t *pending_req, ethernet_frame_t *frame);


/* DO NOT USE THE FUNCTIONS BELOW */

int chirouter_arp_free_pending_req(chirouter_pending_arp_req_t *pending_req);
void* chirouter_arp_process(void *args);


#endif
