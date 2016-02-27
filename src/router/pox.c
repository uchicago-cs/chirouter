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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include "chirouter.h"
#include "pox.h"
#include "utils.h"

int chirouter_pox_process_single_message(chirouter_ctx_t *ctx, char *msg, size_t len);

int chirouter_pox_connect(chirouter_ctx_t *ctx, const char* hostname, const char* port)
{
    struct addrinfo hints, *res, *p;

    /* Get address using getaddrinfo */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0)
    {
        chilog(CRITICAL, "getaddrinfo: Could not resolve %s:%i", hostname, port);
        return 1;
    }

    /* Take first address we can successfully connect to */
    int pox_socket;
    bool success = false;
    for(p = res;p != NULL; p = p->ai_next)
    {
        if ((pox_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            continue;
        }

        if (connect(pox_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(pox_socket);
            continue;
        }

        success = true;
        break;
    }

    freeaddrinfo(res);

    if(success)
    {
        ctx->pox_socket = pox_socket;
        return 0;
    }
    else
    {
        return 1;
    }
}

/* Process messages sent from the POX Controller (src/network/chirouter/network_simulator/pox_controller.py) */
int chirouter_pox_process_messages(chirouter_ctx_t *ctx)
{
    char recv_buffer[4096], msg_buffer[4096];
    int nbytes, rc;
    bool reading_length;

    reading_length = true;
    size_t len = 0;
    int i, bufpos = 0;
    while(1)
    {
        nbytes = recv(ctx->pox_socket, recv_buffer, sizeof(recv_buffer), 0);
        if (nbytes == 0)
        {
            chilog(CRITICAL, "POX Controller closed connection");
            close(ctx->pox_socket);
            return 1;
        }
        else if (nbytes == -1)
        {
            chilog(CRITICAL, "POX Controller socket recv() failed");
            close(ctx->pox_socket);
            return 1;
        }

        chilog(TRACE, "recv() from POX Controller (%i bytes)", nbytes);
        chilog_hex(TRACE, recv_buffer, nbytes);

        i = 0;
        while(i < nbytes)
        {
            if(reading_length)
            {
                if(recv_buffer[i] == ' ')
                {
                    msg_buffer[bufpos] = '\0';
                    len = atoi(msg_buffer);
                    reading_length = false;
                    bufpos = 0;
                    i++;
                }
                else
                {
                    msg_buffer[bufpos++] = recv_buffer[i++];
                }
            }
            else
            {
                msg_buffer[bufpos++] = recv_buffer[i++];
                if(bufpos == len)
                {
                    rc = chirouter_pox_process_single_message(ctx, msg_buffer, len);
                    if(rc != 0)
                    {
                        chilog(CRITICAL, "Error while processing POX message.");
                        close(ctx->pox_socket);
                        return 1;
                    }
                    reading_length = true;
                    bufpos = 0;
                }
            }
        }

    }
}

#define ETHERNET_FRAME '0'
#define ETHERNET_INTERFACE '1'
#define ETHERNET_INTERFACES_DONE '2'

int chirouter_pox_process_ethernet_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len);

int chirouter_pox_process_single_message(chirouter_ctx_t *ctx, char *msg, size_t len)
{
    char type = msg[0];
    int msgpos = 1;
    char iface[256];
    iface[0] = '\0';

    if(type == ETHERNET_FRAME || type == ETHERNET_INTERFACE)
    {
        int i = 0;

        while(msg[msgpos] != ' ')
        {
            iface[i++] = msg[msgpos++];
        }
        iface[i] = '\0';
        msgpos++;
    }

    switch(type) {
        case ETHERNET_FRAME:
        {
            /* Find interface */
            chirouter_interface_t *iface_entry = NULL;
            for(int i=0; i < ctx->num_interfaces; i++)
            {
                if(strncmp(iface, ctx->interfaces[i].name, MAX_IFACE_NAMELEN) == 0)
                {
                    iface_entry = &ctx->interfaces[i];
                    break;
                }
            }

            if(iface_entry == NULL)
            {
                chilog(WARNING, "Received ethernet frame on unknown interface %s", iface);
                return -1;
            }
            else
            {
                chirouter_pox_process_ethernet_frame(ctx, iface_entry, (uint8_t*) &msg[msgpos], len - (msgpos -1));
            }


            break;
        }
        case ETHERNET_INTERFACE:
        {
            /* Get MAC address of interface */
            uint8_t mac[ETHER_ADDR_LEN];

            for (int i = 0; i<ETHER_ADDR_LEN; i++)
            {
                mac[i]=msg[msgpos++];
            }
            msgpos++;

            /* Get IP address of interface */
            char ipbuf[INET_ADDRSTRLEN];
            struct in_addr ip_addr;
            int i = 0;
            while(msg[msgpos] != ' ')
            {
                ipbuf[i++] = msg[msgpos++];
            }
            ipbuf[i] = '\0';
            msgpos++;
            inet_aton(ipbuf, &ip_addr);

            chilog(TRACE, "Received ETHERNET_INTERFACE message from POX Controller");
            chilog(TRACE, "%s %02X:%02X:%02X:%02X:%02X:%02X %s", iface, mac[0], mac[1], mac[2],
                                                                        mac[3], mac[4], mac[5], ipbuf);

            chirouter_ctx_add_iface(ctx, iface, mac, &ip_addr);

            break;
        }
        case ETHERNET_INTERFACES_DONE:
            chilog(TRACE, "Received ETHERNET_INTERFACES_DONE message from POX Controller");

            for(int i=0; i < ctx->num_rtable_entries; i++)
            {
                chirouter_rtable_entry_t *rtable_entry = &ctx->routing_table[i];

                for(int j=0; j < ctx->num_interfaces; j++)
                {
                    chirouter_interface_t *iface_entry = &ctx->interfaces[j];
                    if(strncmp(rtable_entry->interface_name, iface_entry->name, MAX_IFACE_NAMELEN) == 0)
                    {
                        rtable_entry->interface = iface_entry;
                        break;
                    }
                }

                if(rtable_entry->interface == NULL)
                {
                    chilog(CRITICAL, "Routing table included interface %s, but received no such interface from POX", rtable_entry->interface_name);
                    return -1;
                }
            }
            break;
    }

    return 0;
}


int chirouter_pox_process_ethernet_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len)
{
    if(len < ETHER_HDR_LEN)
    {
        chilog(ERROR, "Received an Ethernet frame on interface %s that is %i bytes long (shorter than an Ethernet header)", iface->name, len);
        return -1;
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
        return -1;
    }

    chilog(DEBUG, "Received Ethernet frame on interface %s", iface->name);
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
            return -1;
        }
    }

    if(len < ETHER_FRAME_MIN_LEN)
    {
        chilog(WARNING, "Received an Ethernet frame that is %i bytes long (shorter than the minimum size of an Ethernet frame: %i)", len, ETHER_FRAME_MIN_LEN);
    }

    if(len > ETHER_FRAME_MAX_LEN)
    {
        chilog(WARNING, "Received an Ethernet frame that is %i bytes long (larger than the maximum size of an Ethernet frame: %i)", len, ETHER_FRAME_MAX_LEN);
        return -1;
    }

    /* Create Ethernet frame struct */
    ethernet_frame_t *frame = malloc(sizeof(ethernet_frame_t));

    frame->raw = malloc(len);
    memcpy(frame->raw, msg, len);
    frame->length = len;
    frame->in_interface = iface;

    chirouter_process_ethernet_frame(ctx, frame);

    free(frame->raw);
    free(frame);

    return 0;
}


int chirouter_pox_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len)
{

    if(len < ETHER_HDR_LEN)
    {
        chilog(ERROR, "Trying to send an Ethernet frame on interface %s that is %i bytes long (shorter than an Ethernet header)", iface->name, len);
        return -1;
    }

    chilog(DEBUG, "Sending Ethernet frame on interface %s", iface->name);
    chilog_ethernet(DEBUG, msg, len, LOG_OUTBOUND);

    ethhdr_t* hdr = (ethhdr_t*) msg;

    if (!ethernet_addr_is_equal(hdr->src, iface->mac))
    {
        chilog(ERROR, "Trying to send an Ethernet frame with source address that doesn't match that of interface %s", iface->name);
        return -1;
    }

    /* Create packet to send to POX */
    int msglen = strlen(iface->name)+len+1;
    int numdigits = floor(log10(msglen))+1;
    int totallen = msglen + numdigits + 1;
    char* output = (char*)malloc(sizeof(char)*(totallen));
    memset(output, 0, totallen);
    sprintf(output, "%d %s ", msglen, iface->name);
    int used = strlen(output);
    memcpy(output+used, msg, len);

    int sent = 0;
    while (sent < totallen) {
        int cur = send(ctx->pox_socket, output+sent, totallen-sent, 0);
        sent = sent + cur;
        if (cur == -1) {
            chilog(CRITICAL, "Could not send() to POX");
            exit(1);
        }
    }
    free (output);

    return 0;
}

