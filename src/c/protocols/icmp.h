/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file provides structs and constants to operate on ICMP messages.
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
#include "ipv4.h"

#ifndef PROTOCOLS_ICMP_H_
#define PROTOCOLS_ICMP_H_

#define MAX_ECHO_PAYLOAD (65507u)
#define ICMP_HDR_SIZE (8u)

/* ICMP Types we care about */
#define ICMPTYPE_ECHO_REPLY       (0x00)
#define ICMPTYPE_DEST_UNREACHABLE (0x03)
#define ICMPTYPE_ECHO_REQUEST     (0x08)
#define ICMPTYPE_TIME_EXCEEDED    (0x0B)

/* ICMP Codes we care about */
#define ICMPCODE_DEST_NET_UNREACHABLE       (0x00)
#define ICMPCODE_DEST_HOST_UNREACHABLE      (0x01)
#define ICMPCODE_DEST_PROTOCOL_UNREACHABLE  (0x02)
#define ICMPCODE_DEST_PORT_UNREACHABLE      (0x03)

struct icmp_packet {
  uint8_t type;
  uint8_t code;
  uint16_t chksum;
  union
  {
      struct
      {
          uint16_t identifier;
          uint16_t seq_num;
          uint8_t payload[MAX_ECHO_PAYLOAD];
      } echo;
      struct
      {
          uint16_t unused;
          uint16_t next_mtu;
          uint8_t payload[sizeof(iphdr_t) + 8];
      } dest_unreachable;
      struct
      {
          uint32_t unused;
          uint8_t payload[sizeof(iphdr_t) + 8];
      } time_exceeded;
  };
} __attribute__ ((packed)) ;
typedef struct icmp_packet icmp_packet_t;

#endif /* PROTOCOLS_ICMP_H_ */
