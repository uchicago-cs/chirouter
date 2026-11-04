/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file provides structs and constants to operate on IPv4 headers.
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

#ifndef PROTOCOLS_IPV4_H_
#define PROTOCOLS_IPV4_H_

#include <stdint.h>

#define IPV4_ADDR_LEN       (4)     // Size of IPv4 address in bytes
#define IPV4_VERSION        (4)     // Value of the version field

/* The header length field (ihl) is the number of 32-bit words in
 * the header, which is 5 if the header has no options */
#define IPV4_IHL_NO_OPTIONS (5)

/* Returns the length of an IPv4 header in bytes (including options) */
#define IPV4_HDR_LEN(hdr)   ((size_t) (hdr)->ihl * 4)

/* The order of the version and ihl bit-fields depends on the byte order.
 * We use the byte order macros predefined by GCC and Clang (instead of
 * the ones in <endian.h>, which is not available on all platforms) */
struct chirouter_iphdr
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t  ihl: 4,
             version: 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t  version: 4,
             ihl: 4;
#else
#error __BYTE_ORDER__ must be __ORDER_LITTLE_ENDIAN__ or __ORDER_BIG_ENDIAN__
#endif
    uint8_t tos;         // Type of service
    uint16_t len;        // Total Length
    uint16_t id;         // Identification
    uint16_t off;        // Fragment flags + Fragment Offset
    uint8_t ttl;         // Time to Live
    uint8_t proto;       // Protocol
    uint16_t cksum;      // Checksum
    uint32_t src;        // Source Address
    uint32_t dst;        // Destination Address
} __attribute__((packed));
typedef struct chirouter_iphdr iphdr_t;

#endif /* PROTOCOLS_IPV4_H_ */
