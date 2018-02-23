/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file provides structs, constants, and macros to
 *  operate on Ethernet headers and frames.
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

#include <stdint.h>

#ifndef PROTOCOLS_ETHERNET_H_
#define PROTOCOLS_ETHERNET_H_

#define ETHER_ADDR_LEN       (6)     /* Size of Ethernet address in bytes */
#define ETHER_HDR_LEN        (14)    /* Size of Ethernet header in bytes */
#define ETHER_FRAME_MIN_LEN  (60)    /* Minimum size of an Ethernet frame (not including CRC) */
#define ETHER_FRAME_MAX_LEN  (1514)  /* Maximum size of an Ethernet frame (not including CRC) */

/* Ethertypes we care about */
#define ETHERTYPE_IP         (0x0800)      /* IPv4 */
#define ETHERTYPE_ARP        (0x0806)      /* ARP */
#define ETHERTYPE_IPV6       (0x86DD)      /* IPv6 */

/* Ethernet header */
struct ethhdr {
    uint8_t   dst[ETHER_ADDR_LEN];
    uint8_t   src[ETHER_ADDR_LEN];
    uint16_t  type;
} __attribute__((packed));
typedef struct ethhdr ethhdr_t;

/* Returns pointer to the start of a frame's payload */
#define ETHER_PAYLOAD_START(frame) (frame + sizeof(ethhdr_t))


#endif /* PROTOCOLS_ETHERNET_H_ */
