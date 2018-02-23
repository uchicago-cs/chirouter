/*
 *  chirouter - A simple, testable IP router
 *
 *  This header file defines functions for creating a pcap
 *  file with all the ethernet frames that flow through the routers
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

#ifndef PCAP_H
#define PCAP_H

#include "server.h"
#include "chirouter.h"

/* Packet direction */
typedef enum
{
    PCAP_UNSPECIFIED = 0,
    PCAP_INBOUND = 1,
    PCAP_OUTBOUND = 2
} pcap_packet_direction_t;


/*
 * chirouter_pcap_write_section_header - Writes a pcapng section header
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_pcap_write_section_header(server_ctx_t *ctx);


/*
 * chirouter_pcap_write_interfaces
 *
 * Writes the interface description blocks for all the interfaces
 * from all the routers.
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_pcap_write_interfaces(server_ctx_t *ctx);


/*
 * chirouter_pcap_write_frame - Writes an Ethernet frame to the capture file
 *
 * ctx: Server context
 *
 * iface: Interface the frame was sent on
 *
 * msg: Pointer to the frame (including the Ethernet header and payload)
 *
 * len: Length in bytes of the frame.
 *
 * dir: Direction of the frame (inbound or outbound)
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_pcap_write_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len, pcap_packet_direction_t dir);


#endif
