/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file provides structs and constants to operate on ARP headers.
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

#ifndef PROTOCOLS_ARP_H_
#define PROTOCOLS_ARP_H_

#include "ethernet.h"


/* ARP Opcodes */
#define ARP_OP_REQUEST      (0x0001)
#define ARP_OP_REPLY        (0x0002)

/* ARP hrd codes */
#define ARP_HRD_ETHERNET    (0x0001)


/* The following struct follows the specification in RFC 826,
 * but the sizes of sha, spa, tha, tpa are such that this
 * struct can only be used to convert Ethernet addresses to
 * IPv4 addresses.
 */
struct arp_packet
{
    uint16_t  hrd;                   /* Hardware address space  */
    uint16_t  pro;                   /* Protocol address space  */
    uint8_t   hln;                   /* Byte length of each hardware address */
    uint8_t   pln;                   /* Byte length of each protocol address */
    uint16_t  op;                    /* opcode  */
    uint8_t   sha[ETHER_ADDR_LEN];   /* Hardware address of sender of this packet  */
    uint32_t  spa;                   /* Protocol address of sender of this packet  */
    uint8_t   tha[ETHER_ADDR_LEN];   /* Hardware address of target of this packet (if known) */
    uint32_t  tpa;                   /* Protocol address of target. */
} __attribute__ ((packed)) ;
typedef struct arp_packet arp_packet_t;

#endif /* SRC_ROUTER_PROTOCOLS_ARP_H_ */
