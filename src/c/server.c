/*
 *  chirouter - A simple, testable IP router
 *
 *  This server listens on connections from the POX controller.
 *  Once established, this connection starts with the POX
 *  controller sending information about all the routers
 *  we have to run and, after that, is used to send/receive
 *  Ethernet frames from/to those routers.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "server.h"
#include "log.h"
#include "utils.h"
#include "pcap.h"
#include "arp.h"


/* Forward declarations */
int chirouter_server_process_messages(server_ctx_t *ctx);
int chirouter_server_process_single_message(server_ctx_t *ctx, chirouter_msg_t *msg);
int chirouter_server_process_ethernet_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);
int chirouter_server_ctx_free_routers(server_ctx_t *ctx);


/*
 * chirouter_server_ctx_init - Initializes a server context
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 */
int chirouter_server_ctx_init(server_ctx_t **ctx)
{
    /* Initialize all pointers and sizes to zero */
    *ctx = calloc(1, sizeof(server_ctx_t));

    if(*ctx == NULL)
        return -1;

    return 0;
}


/*
 * chirouter_server_setup - Sets up the chirouter server socket
 *
 * ctx: Server context
 *
 * port: TCP port to listen on
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_setup(server_ctx_t *ctx, char *port)
{
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int yes = 1;

    if (getaddrinfo(NULL, port, &hints, &res) != 0)
    {
        chilog(CRITICAL, NULL, "getaddrinfo() failed");
        return -1;
    }

    for(p = res; p != NULL; p = p->ai_next)
    {
        if ((ctx->server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            chilog(WARNING, NULL, "Could not open socket");
            continue;
        }

        if (setsockopt(ctx->server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            chilog(WARNING, NULL, "Socket setsockopt() failed");
            close(ctx->server_socket);
            continue;
        }

        if (bind(ctx->server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            chilog(WARNING, NULL, "Socket bind() failed");
            close(ctx->server_socket);
            continue;
        }

        if (listen(ctx->server_socket, 5) == -1)
        {
            chilog(WARNING, NULL, "Socket listen() failed");
            close(ctx->server_socket);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        chilog(CRITICAL, NULL, "Could not find a socket to bind to.");
        return -1;
    }

    return 0;
}


/*
 * chirouter_server_send_msg - Sends a message to the controller
 *
 * ctx: Server context
 *
 * msg: Message to send
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_send_msg(server_ctx_t *ctx, chirouter_msg_t *msg)
{
    int sent = 0;
    int totallen = 4 + ntohs(msg->payload_length);
    char *buf = (char *) msg;

    while (sent < totallen) {
        int cur = send(ctx->client_socket, buf+sent, totallen-sent, 0);
        sent = sent + cur;
        if (cur == -1) {
            chilog(CRITICAL, "Could not send message to controller");
            return -1;
        }
    }

    return 0;
}


/*
 * chirouter_server_run - Run the chirouter server
 *
 * The chirouter server is designed to handle only one connection at a time,
 * since it should only be associated with one controller at any given point.
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_run(server_ctx_t *ctx)
{
    struct sockaddr_storage *client_addr;
    int client_socket, rc;
    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    socklen_t sa_size = sizeof(struct sockaddr_storage);

    client_addr = calloc(1, sa_size);
    while (1)
    {
        chilog(INFO, "Waiting for connection from controller...");
        if ((client_socket = accept(ctx->server_socket, (struct sockaddr *) client_addr, &sa_size)) == -1)
        {
            free(client_addr);
            chilog(CRITICAL, "Could not accept() connection");
            return -1;
        }

        rc = getnameinfo((struct sockaddr *) client_addr, sa_size,
                         ip, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

        if(rc)
            chilog(INFO, "Controller connected");
        else
            chilog(INFO, "Controller connected from %s:%s", ip, port);


        ctx->state = HELLO_WAIT;
        ctx->client_socket = client_socket;

        rc = chirouter_server_process_messages(ctx);

        if(rc == -1)
        {
            chilog(CRITICAL, "Error while processing messages");
            return -1;
        }
        else if (rc == 0)
        {
            chilog(INFO, "Controller has disconnected.");

            ctx->state = HELLO_WAIT;
            rc = chirouter_server_ctx_free_routers(ctx);
            if(rc == -1)
            {
                chilog(CRITICAL, "Error while freeing router resources");
                return -1;
            }
        }
    }
    free(client_addr);
    return 0;
}


/*
 * chirouter_server_process_messages - Processes messages received by the server
 *
 * ctx: Server context
 *
 * Returns:
 *  0 if the client closed the connection normally
 *  -1 if an error occurred
 *
 */
int chirouter_server_process_messages(server_ctx_t *ctx)
{
    char recv_buffer[4096], msg_buffer[4096];
    chirouter_msg_t *msg;
    int nbytes, rc;
    bool reading_header = true;
    size_t len;
    int i, bufpos = 0;

    while(1)
    {
        nbytes = recv(ctx->client_socket, recv_buffer, sizeof(recv_buffer), 0);
        if (nbytes == 0)
        {
            chilog(DEBUG, "Controller closed connection");
            close(ctx->client_socket);
            return 0;
        }
        else if (nbytes == -1)
        {
            chilog(CRITICAL, "recv() from controller failed");
            close(ctx->client_socket);
            return -1;
        }

        chilog(TRACE, "recv() from controller (%i bytes)", nbytes);
        chilog_hex(TRACE, recv_buffer, nbytes);

        i = 0;
        len = 0;
        while(i < nbytes)
        {
            msg_buffer[bufpos++] = recv_buffer[i++];

            if(reading_header && bufpos==4)
            {
                /* We have a header */
                msg = (chirouter_msg_t *) msg_buffer;
                len = ntohs(msg->payload_length);
                reading_header = false;
            }

            if(!reading_header && bufpos == (4+len))
            {
                /* We have a complete message */
                rc = chirouter_server_process_single_message(ctx, msg);
                if(rc)
                {
                    chilog(CRITICAL, "Error while processing message.");
                    close(ctx->client_socket);
                    return -1;
                }
                reading_header = true;
                bufpos = 0;
                len = 0;
            }
        }

    }
}


/*
 * chirouter_server_process_single_message - Process a single message
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_process_single_message(server_ctx_t *ctx, chirouter_msg_t *msg)
{
    int rc;
    chirouter_msg_t reply_msg;
    uint16_t payload_len = ntohs(msg->payload_length);

    switch(msg->type)
    {
    case MSG_TYPE_HELLO:
    {
        if(ctx->state != HELLO_WAIT)
        {
            chilog(CRITICAL, "Received a HELLO message but not in the HELLO_WAIT state");
            return -1;
        }

        /* Send back HELLO message */
        reply_msg.type = MSG_TYPE_HELLO;
        reply_msg.subtype = FROM_ROUTER;
        reply_msg.payload_length = 0;

        rc = chirouter_server_send_msg(ctx, &reply_msg);
        if(rc)
        {
            chilog(CRITICAL, "Could not send HELLO message");
            return -1;
        }

        ctx->state = CONFIG;
        break;
    }
    case MSG_TYPE_ROUTERS:
    {
        if(ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received a ROUTERS message but not in the CONFIG state");
            return -1;
        }

        uint8_t nrouters = msg->routers.nrouters;

        ctx->max_routers = nrouters;
        ctx->num_routers = 0;
        ctx->routers = calloc(nrouters, sizeof(chirouter_ctx_t));

        for(int i=0; i < nrouters; i++)
        {
            chirouter_ctx_init(&ctx->routers[i]);
            ctx->routers[i].server = ctx;
        }

        break;
    }
    case MSG_TYPE_ROUTER:
    {
        if(ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received a ROUTER message but not in the CONFIG state");
            return -1;
        }

        if(msg->router.r_id != ctx->num_routers)
        {
            chilog(CRITICAL, "Received unexpected ROUTER message (Router ID: %d)", msg->router.r_id);
            return -1;
        }

        chilog(TRACE, "Processing Router ID %d", msg->router.r_id);

        chirouter_ctx_t *r = &ctx->routers[msg->router.r_id];

        r->r_id = msg->router.r_id;

        int name_len = payload_len - 3;
        memcpy(r->name, msg->router.name, name_len);
        r->name[name_len] = '\0';

        r->max_interfaces = msg->router.num_interfaces;
        r->num_interfaces = 0;
        r->interfaces = calloc(r->max_interfaces, sizeof(chirouter_interface_t));

        r->max_rtable_entries = msg->router.len_rtable;
        r->num_rtable_entries = 0;
        r->routing_table = calloc(r->max_rtable_entries, sizeof(chirouter_rtable_entry_t));

        ctx->num_routers++;

        break;
    }
    case MSG_TYPE_INTERFACE:
    {
        if(ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received an INTERFACE message but not in the CONFIG state");
            return -1;
        }

        if(msg->interface.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->interface.r_id);
            return -1;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->interface.r_id];

        if(msg->interface.iface_id != r->num_interfaces)
        {
            chilog(CRITICAL, "Received unexpected INTERFACE message (Interface ID: %d)", msg->interface.iface_id);
            return -1;
        }

        chirouter_interface_t *iface = &r->interfaces[msg->interface.iface_id];

        chilog(TRACE, "Processing Interface ID %d in Router ID %d",  msg->interface.iface_id,  msg->interface.r_id);

        iface->pox_iface_id = msg->interface.iface_id;

        int name_len = payload_len - 12;
        memcpy(iface->name, msg->interface.name, name_len);
        iface->name[name_len] = '\0';
        memcpy(iface->mac, msg->interface.hwaddr, ETHER_ADDR_LEN);
        memcpy(&iface->ip, &msg->interface.ipaddr, sizeof(struct in_addr));

        r->num_interfaces++;

        break;
    }
    case MSG_TYPE_RTABLE_ENTRY:
    {
        if(ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received a ROUTING TABLE ENTRY message but not in the CONFIG state");
            return -1;
        }

        if(msg->rtable_entry.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->rtable_entry.r_id);
            return -1;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->rtable_entry.r_id];

        if(msg->rtable_entry.iface_id >= r->num_interfaces)
        {
            chilog(CRITICAL, "Received invalid Interface ID: %d", msg->rtable_entry.iface_id);
            return -1;
        }

        if(r->num_rtable_entries >= r->max_rtable_entries)
        {
            chilog(CRITICAL, "Received ROUTING TABLE ENTRY but already have %d expected entries", r->max_rtable_entries);
            return -1;
        }

        chilog(TRACE, "Processing Routing Table Entry in Router ID %d (with Interface ID %d)", msg->rtable_entry.r_id, msg->rtable_entry.iface_id);

        chirouter_interface_t *iface = &r->interfaces[msg->rtable_entry.iface_id];
        chirouter_rtable_entry_t *rtentry = &r->routing_table[r->num_rtable_entries];

        rtentry->dest.s_addr = msg->rtable_entry.dest;
        rtentry->mask.s_addr = msg->rtable_entry.mask;
        rtentry->gw.s_addr = msg->rtable_entry.gw;
        rtentry->metric = ntohs(msg->rtable_entry.metric);
        rtentry->interface = iface;

        r->num_rtable_entries++;
        break;
    }
    case MSG_TYPE_END_CONFIG:
    {
        if(ctx->num_routers != ctx->max_routers)
        {
            chilog(CRITICAL, "Expected %d routers but received only %d", ctx->max_routers, ctx->num_routers);
            return -1;
        }

        chilog(INFO, "Received %i routers", ctx->num_routers);

        chilog(INFO, "--------------------------------------------------------------------------------");
        for(int i=0; i < ctx->num_routers; i++)
        {
            chirouter_ctx_t *r = &ctx->routers[i];

            if(r->num_interfaces != r->max_interfaces)
            {
                chilog(CRITICAL, "Router %d: Expected %d interfaces but received only %d", i, r->max_interfaces, r->num_interfaces);
                return -1;
            }

            chirouter_ctx_log(&ctx->routers[i], INFO);
            pthread_create(&r->arp_thread, NULL, chirouter_arp_process, r);
            chilog(INFO, "--------------------------------------------------------------------------------");
        }

        if(ctx->pcap)
        {
            chirouter_pcap_write_section_header(ctx);
            chirouter_pcap_write_interfaces(ctx);
        }

        ctx->state = RUNNING;
        break;
    }
    case MSG_TYPE_ETHERNET_FRAME:
    {
        if(ctx->state != RUNNING)
        {
            chilog(CRITICAL, "Received an ETHERNET FRAME message but not in the RUNNING state");
            return -1;
        }

        if(msg->ethernet.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->ethernet.r_id);
            return -1;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->ethernet.r_id];

        if(msg->ethernet.iface_id >= r->num_interfaces)
        {
            chilog(CRITICAL, "Received invalid Interface ID: %d", msg->ethernet.iface_id);
            return -1;
        }

        chirouter_interface_t *iface = &r->interfaces[msg->ethernet.iface_id];

        rc = chirouter_server_process_ethernet_frame(r, iface, msg->ethernet.frame, ntohs(msg->ethernet.frame_len));
        if(rc == -1)
        {
            chilog(CRITICAL, "Error when processing Ethernet frame received from controller.");
            return -1;
        }

    }

    }

    return 0;
}


/*
 * chirouter_server_process_ethernet_frame - Process an Ethernet frame received in an ETHERNET FRAME message
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
 *  0 on success
 *  -1 if a critical error happens
 *  1 if a non-critical error happens
 *
 */
int chirouter_server_process_ethernet_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len)
{
    int rc;

    if(len < ETHER_HDR_LEN)
    {
        chilog(ERROR, "Received an Ethernet frame on interface %s that is %i bytes long (shorter than an Ethernet header)", iface->name, len);
        return 1;
    }

    ethhdr_t *hdr = (ethhdr_t *) msg;

    bool is_broadcast = true;
    for(int i=0; i <ETHER_ADDR_LEN; i++)
    {
        if(hdr->dst[i] != 0xFF)
        {
            is_broadcast = false;
            break;
        }
    }

    bool is_multicast = (hdr->dst[0] & 0x01);

    /* If this is a multicast frame, don't process it, and only log it at the TRACE level */
    if (is_multicast && !is_broadcast)
    {
        chilog(TRACE, "Received a multicast Ethernet frame. Ignoring.");
        chilog_ethernet(TRACE, msg, len, LOG_INBOUND);
        return 1;
    }

    chilog(DEBUG, "Received Ethernet frame on interface %s-%s", ctx->name, iface->name);
    chilog_ethernet(DEBUG, msg, len, LOG_INBOUND);

    /* Validate ethernet address */
    for(int i=0; i <ETHER_ADDR_LEN; i++)
    {
        if(hdr->dst[i] != iface->mac[i] && !is_broadcast)
        {
            chilog(WARNING, "Received a non-broadcast Ethernet frame with a destination address that doesn't match the interface");
            chilog(WARNING, "Interface %s address: %02X:%02X:%02X:%02X:%02X:%02X", iface->name, iface->mac[0], iface->mac[1], iface->mac[2],
                                                                                                iface->mac[3], iface->mac[4], iface->mac[5]);
            chilog(WARNING, "Ethernet destination address: %02X:%02X:%02X:%02X:%02X:%02X", hdr->dst[0], hdr->dst[1], hdr->dst[2],
                                                                                           hdr->dst[3], hdr->dst[4], hdr->dst[5]);
            return 1;
        }
    }

    if(len < ETHER_FRAME_MIN_LEN)
    {
        chilog(TRACE, "Received an Ethernet frame that is %i bytes long (shorter than the minimum size of an Ethernet frame: %i)", len, ETHER_FRAME_MIN_LEN);
    }

    if(len > ETHER_FRAME_MAX_LEN)
    {
        chilog(WARNING, "Received an Ethernet frame that is %i bytes long (larger than the maximum size of an Ethernet frame: %i)", len, ETHER_FRAME_MAX_LEN);
        return 1;
    }

    /* Create Ethernet frame struct */
    ethernet_frame_t *frame = calloc(1, sizeof(ethernet_frame_t));

    frame->raw = calloc(1, len);
    memcpy(frame->raw, msg, len);
    frame->length = len;
    frame->in_interface = iface;

    if(ctx->server->pcap)
        chirouter_pcap_write_frame(ctx, iface, msg, len, PCAP_INBOUND);

    rc = chirouter_process_ethernet_frame(ctx, frame);

    free(frame->raw);
    free(frame);

    if (rc == -1)
    {
        chilog(CRITICAL, "Critical error while processing Ethernet frame");
        return -1;
    }

    return 0;
}


/* See chirouter.h */
int chirouter_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *frame, size_t frame_len)
{
    if(frame_len < ETHER_HDR_LEN)
    {
        chilog(ERROR, "Trying to send an Ethernet frame on interface %s that is %i bytes long (shorter than an Ethernet header)", iface->name, frame_len);
        return 1;
    }

    if(frame_len > ETHER_FRAME_MAX_LEN)
    {
        chilog(ERROR, "Trying to send an Ethernet frame on interface %s that is %i bytes long (larger than the maximum Ethernet frame size)", iface->name, frame_len);
        return 1;
    }

    chilog(DEBUG, "Sending Ethernet frame on interface %s-%s", ctx->name, iface->name);
    chilog_ethernet(DEBUG, frame, frame_len, LOG_OUTBOUND);

    ethhdr_t* hdr = (ethhdr_t*) frame;

    if (!ethernet_addr_is_equal(hdr->src, iface->mac))
    {
        chilog(ERROR, "Trying to send an Ethernet frame with source address that doesn't match that of interface %s", iface->name);
        return 1;
    }

    if(ctx->server->pcap)
        chirouter_pcap_write_frame(ctx, iface, frame, frame_len, PCAP_OUTBOUND);

    chirouter_msg_t msg;

    msg.type = MSG_TYPE_ETHERNET_FRAME;
    msg.subtype = FROM_ROUTER;
    msg.payload_length = htons(4+frame_len);
    msg.ethernet.r_id = ctx->r_id;
    msg.ethernet.iface_id = iface->pox_iface_id;
    msg.ethernet.frame_len = htons(frame_len);
    memcpy(msg.ethernet.frame, frame, frame_len);

    return chirouter_server_send_msg(ctx->server, &msg);
}


/*
 * chirouter_server_ctx_free_routers - Frees router resources
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_ctx_free_routers(server_ctx_t *ctx)
{
    int rc;

    for(int i=0; i < ctx->num_routers; i++)
    {
        rc = chirouter_ctx_destroy(&ctx->routers[i]);
        if(rc)
        {
            chilog(CRITICAL, "Could not free router resource");
            return -1;
        }
    }

    free(ctx->routers);

    ctx->routers = NULL;
    ctx->num_routers = 0;
    ctx->max_routers = 0;

    return 0;
}


/*
 * chirouter_server_ctx_destroy - Frees server resources
 *
 * ctx: Server context
 *
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_server_ctx_destroy(server_ctx_t *ctx)
{
    int rc;

    rc = chirouter_server_ctx_free_routers(ctx);
    if(rc)
    {
        chilog(CRITICAL, "Could not free router resources");
        return -1;
    }

    return 0;
}

