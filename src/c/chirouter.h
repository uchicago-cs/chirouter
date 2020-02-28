/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file defines the main data structures used by the
 *  router, as well as some functions that operate on these data
 *  structures
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

#ifndef CHIROUTER_H
#define CHIROUTER_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>

#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/ipv4.h"
#include "protocols/icmp.h"
#include "log.h"

#define MAX_ROUTER_NAMELEN (8u)
#define MAX_IFACE_NAMELEN (32u)
#define MAX_NUM_INTERFACES (65536u)
#define MAX_NUM_RTABLE_ENTRIES (65536u)
#define ARPCACHE_SIZE (100u)
#define ARPCACHE_ENTRY_TIMEOUT (15u)


typedef struct server_ctx server_ctx_t;


/* Represents a single Ethernet interface */
typedef struct chirouter_interface
{
    /* Interface name (eth0, eth1, ...) */
    char name[MAX_IFACE_NAMELEN + 1];

    /* MAC address */
    uint8_t mac[ETHER_ADDR_LEN];

    /* IP address */
    struct in_addr ip;

    /*** NOTE: You should NOT use or modify the fields below ***/

    /* Interface ID for POX controller */
    uint8_t pox_iface_id;

    /* Interface ID for capture file */
    uint32_t pcap_iface_id;

} chirouter_interface_t;


/* Represents an *inbound* Ethernet frame */
typedef struct ethernet_frame
{
    /* Pointer to byte array with raw Ethernet frame */
    uint8_t *raw;

    /* Length of the frame */
    size_t length;

    /* Interface on which the frame arrived */
    chirouter_interface_t *in_interface;
} ethernet_frame_t;


/* Represents an entry in the routing table */
typedef struct chirouter_rtable_entry
{
    /* Destination subnet ip */
    struct in_addr dest;

    /* Destination subnet mask */
    struct in_addr mask;

    /* Gateway ip to destination */
    struct in_addr gw;

    /* Metric */
    uint16_t metric;

    /* Interface that is connected to this subnet */
    chirouter_interface_t *interface;
} chirouter_rtable_entry_t;


/* Represents an entry in the ARP cache */
typedef struct chirouter_arpcache_entry
{
    /* MAC address */
    uint8_t mac[ETHER_ADDR_LEN];

    /* IP address */
    struct in_addr ip;

    /* Time when this entry was created */
    time_t time_added;

    /* Is this a valid entry?
     * If an entry is not valid, this means
     * it is available and can be used to store
     * a new (valid) entry. */
    bool valid;
} chirouter_arpcache_entry_t;


/* Used to store withheld frames (using a linked list)
 * in a pending ARP request. */
typedef struct withheld_frame
{
    /* Pointer to the withheld Ethernet frame */
    ethernet_frame_t *frame;

    /* List pointers */
    struct withheld_frame *prev;
    struct withheld_frame *next;
} withheld_frame_t;

/* Represents a pending ARP request for which
 * we have not yet received an ARP reply */
typedef struct chirouter_pending_arp_req
{
    /* IP address being queried */
    struct in_addr ip;

    /* Interface on which the ARP request was sent */
    chirouter_interface_t *out_interface;

    /* The number of times this ARP request has been sent,
     * and the last time we sent the request */
    uint32_t times_sent;
    time_t last_sent;

    /* List of Ethernet frames containing IP datagrams destined
     * to "ip", but which we cannot yet send because we do not
     * know the MAC address corresponding to that IP address */
    withheld_frame_t *withheld_frames;

    /* List pointers */
    struct chirouter_pending_arp_req *prev;
    struct chirouter_pending_arp_req *next;
} chirouter_pending_arp_req_t;


/* The chirouter context. Contains all the router data structures */
typedef struct chirouter_ctx
{
    /* Router name */
    char name[MAX_ROUTER_NAMELEN + 1];

    /* Number of Ethernet interfaces */
    uint16_t num_interfaces;

    /* Pointer to array of interfaces. Array is guaranteed to
     * be of size "num_interfaces" */
    chirouter_interface_t* interfaces;

    /* Number of routing table entries */
    uint16_t num_rtable_entries;

    /* Pointer to array of routing table entries. Array is
     * guaranteed to be of size "num_rtable_entries" */
    chirouter_rtable_entry_t* routing_table;

    /* ARP cache */
    chirouter_arpcache_entry_t arpcache[ARPCACHE_SIZE];

    /* List of pending ARP requests */
    chirouter_pending_arp_req_t* pending_arp_reqs;


    /* Mutex to protect both the ARP cache and the list of
     * pending ARP requests. Lock this mutex if *either* of
     * these data structures are going to be used */
    pthread_mutex_t lock_arp;


    /*** NOTE: You should NOT use or modify the fields below ***/

    /* ARP thread */
    pthread_t arp_thread;

    /* Used during configuration of router */
    uint16_t max_interfaces;
    uint16_t max_rtable_entries;

    /* Router ID for POX controller */
    uint8_t r_id;

    /* Server context */
    server_ctx_t *server;
} chirouter_ctx_t;


/*
 * chirouter_send_frame - Send an Ethernet frame on one of the router's interfaces
 *
 * ctx: Router context
 *
 * iface: Interface to send the frame on.
 *
 * msg: Pointer to the frame (including the Ethernet header and payload)
 *
 * len: Length in bytes of the frame.
 *
 * Returns:
 *
 *   0 on success,
 *
 *   1 if a non-critical error happens
 *
 *   -1 if a critical error happens
 *
 */
int chirouter_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);


/* Note: You should not call any of the functions below */

int chirouter_ctx_init(chirouter_ctx_t *ctx);
int chirouter_ctx_load_rtable(chirouter_ctx_t *ctx, const char* rtable_filename);
int chirouter_ctx_add_iface(chirouter_ctx_t *ctx, const char* iface, uint8_t mac[ETHER_ADDR_LEN], struct in_addr *ip);
void chirouter_ctx_log(chirouter_ctx_t *ctx, loglevel_t loglevel);
int chirouter_ctx_destroy(chirouter_ctx_t *ctx);

int chirouter_process_ethernet_frame(chirouter_ctx_t *ctx, ethernet_frame_t *frame);

#endif
