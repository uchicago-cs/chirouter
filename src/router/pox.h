/*
 *  chirouter - A simple, testable IP router
 *
 *  Functions to communicate with POX
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
 *
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

#ifndef __POX_H
#define __POX_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "chirouter.h"


/*
 * chirouter_pox_send_frame - Send an Ethernet frame on one of the router's interfaces
 *
 * ctx: Router context
 *
 * iface: Interface to send the frame on.
 *
 * msg: Pointer to the frame (including the Ethernet header and payload)
 *
 * len: Length in bytes of the frame.
 *
 * Returns: 0 on success, 1 on error.
 */
int chirouter_pox_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);



/* Do not use any of the structs or functions below */

#define INCOMING_PACKET '0'
#define IFACE_MSG '1'
#define IFACE_DONE '2'


typedef struct {
	uint8_t type; //comm msg type.
} pox_packet;

typedef struct {
	uint8_t type;
	char* iface;
	uint8_t* msg;
	int msglen;
} incoming_ethernet_packet;

typedef struct {
	uint8_t type;
	char* iface;
	unsigned char addr[ETHER_ADDR_LEN];
	uint32_t ip;
} iface_defn_packet;

int chirouter_pox_connect(chirouter_ctx_t *ctx, const char* hostname, const char* port);
int chirouter_pox_process_messages(chirouter_ctx_t *ctx);
int chirouter_pox_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);


#endif
