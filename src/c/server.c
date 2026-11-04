/*
 *  chirouter - A simple, testable IP router
 *
 *  This server listens on connections from the controller.
 *  Once established, this connection starts with the
 *  controller sending information about all the routers
 *  we have to run and, after that, is used to send/receive
 *  Ethernet frames from/to those routers.
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
#include <errno.h>

#include "server.h"
#include "log.h"
#include "utils.h"
#include "pcap.h"
#include "arp.h"


/* Maximum number of pending connections on the server socket */
#define LISTEN_BACKLOG (5)

/* Size of the buffer used to receive data from the controller */
#define RECV_BUFFER_SIZE (4096)

/* Forward declarations */
static int chirouter_server_process_messages(server_ctx_t *ctx);
static int chirouter_server_process_single_message(server_ctx_t *ctx,
        chirouter_msg_t *msg);
static int chirouter_server_process_ethernet_frame(chirouter_ctx_t *ctx,
        chirouter_interface_t *iface, uint8_t *msg, size_t len);
static int chirouter_server_ctx_free_routers(server_ctx_t *ctx);
static bool chirouter_server_payload_len_is_valid(const chirouter_msg_t *msg,
        uint16_t payload_len);


/* See server.h */
int chirouter_server_ctx_init(server_ctx_t **ctx)
{
    /* Initialize all pointers and sizes to zero */
    *ctx = xcalloc(1, sizeof(server_ctx_t));

    (*ctx)->server_socket = -1;
    (*ctx)->client_socket = -1;
    atomic_init(&(*ctx)->stopping, false);

    pthread_mutex_init(&(*ctx)->lock_send, NULL);
    pthread_mutex_init(&(*ctx)->lock_pcap, NULL);

    return CHIROUTER_OK;
}


/* See server.h */
int chirouter_server_setup(server_ctx_t *ctx, const char *port)
{
    struct addrinfo hints, *res, *p;
    int rc, last_errno = 0;
    char errbuf[STRERROR_BUF_LEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    int yes = 1;

    if ((rc = getaddrinfo(NULL, port, &hints, &res)) != 0)
    {
        chilog(CRITICAL, "getaddrinfo() failed: %s", gai_strerror(rc));
        return CHIROUTER_CRITICAL_ERROR;
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((ctx->server_socket = socket(p->ai_family, p->ai_socktype,
                                         p->ai_protocol)) == -1)
        {
            last_errno = errno;
            chilog(WARNING, "Could not open socket: %s",
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            continue;
        }

        if (setsockopt(ctx->server_socket, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1)
        {
            last_errno = errno;
            chilog(WARNING, "Socket setsockopt() failed: %s",
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            close(ctx->server_socket);
            continue;
        }

        if (bind(ctx->server_socket, p->ai_addr, p->ai_addrlen) == -1)
        {
            last_errno = errno;
            chilog(WARNING, "Socket bind() failed: %s",
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            close(ctx->server_socket);
            continue;
        }

        if (listen(ctx->server_socket, LISTEN_BACKLOG) == -1)
        {
            last_errno = errno;
            chilog(WARNING, "Socket listen() failed: %s",
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            close(ctx->server_socket);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL)
    {
        chilog(CRITICAL, "Could not find a socket to bind to on port %s: %s", port,
               chirouter_strerror(last_errno, errbuf, sizeof(errbuf)));
        return CHIROUTER_CRITICAL_ERROR;
    }

    return CHIROUTER_OK;
}


/*
 * chirouter_server_send_msg - Sends a message to the controller
 *
 * ctx: Server context
 *
 * msg: Message to send
 *
 * Returns: CHIROUTER_OK on success, CHIROUTER_CRITICAL_ERROR if an error
 *          happens.
 *
 */
static int chirouter_server_send_msg(server_ctx_t *ctx, chirouter_msg_t *msg)
{
    size_t sent = 0;
    size_t totallen = MSG_HDR_LEN + ntohs(msg->payload_length);
    char *buf = (char *) msg;

    /* Frames can be sent from both the main thread and the ARP threads,
     * so we must make sure messages are not interleaved on the socket */
    pthread_mutex_lock(&ctx->lock_send);

    while (sent < totallen)
    {
        ssize_t cur = send(ctx->client_socket, buf + sent, totallen - sent, 0);
        if (cur == -1)
        {
            pthread_mutex_unlock(&ctx->lock_send);
            chilog(CRITICAL, "Could not send message to Mininet");
            return CHIROUTER_CRITICAL_ERROR;
        }
        sent += (size_t) cur;
    }

    pthread_mutex_unlock(&ctx->lock_send);

    return CHIROUTER_OK;
}


/* See server.h */
int chirouter_server_run(server_ctx_t *ctx)
{
    struct sockaddr_storage *client_addr;
    int client_socket, rc;
    char ip[NI_MAXHOST];
    char port[NI_MAXSERV];
    socklen_t sa_size;
    bool stopping;
    char errbuf[STRERROR_BUF_LEN];

    client_addr = xcalloc(1, sizeof(struct sockaddr_storage));
    while (!atomic_load(&ctx->stopping))
    {
        chilog(INFO, "Waiting for connection from Mininet...");
        sa_size = sizeof(struct sockaddr_storage);
        client_socket = accept(ctx->server_socket,
                               (struct sockaddr *) client_addr, &sa_size);
        if (client_socket == -1)
        {
            if (atomic_load(&ctx->stopping))
                break;

            free(client_addr);
            chilog(CRITICAL, "Could not accept() connection: %s",
                   chirouter_strerror(errno, errbuf, sizeof(errbuf)));
            return CHIROUTER_CRITICAL_ERROR;
        }

        /* If chirouter_server_stop is called while we are accepting the
         * connection, it won't see the client socket, so we need to check
         * whether we are stopping after setting it */
        pthread_mutex_lock(&ctx->lock_send);
        ctx->client_socket = client_socket;
        stopping = atomic_load(&ctx->stopping);
        if (stopping)
        {
            close(ctx->client_socket);
            ctx->client_socket = -1;
        }
        pthread_mutex_unlock(&ctx->lock_send);

        if (stopping)
            break;

        rc = getnameinfo((struct sockaddr *) client_addr, sa_size,
                         ip, NI_MAXHOST, port, NI_MAXSERV,
                         NI_NUMERICHOST | NI_NUMERICSERV);

        if (rc)
            chilog(INFO, "Mininet connected");
        else
            chilog(INFO, "Mininet connected from %s:%s", ip, port);


        ctx->state = HELLO_WAIT;

        rc = chirouter_server_process_messages(ctx);

        if (rc == CHIROUTER_CRITICAL_ERROR)
        {
            chilog(CRITICAL, "Error while processing messages");
        }
        else
        {
            chilog(INFO, "Mininet has disconnected.");
        }

        ctx->state = HELLO_WAIT;
        rc = chirouter_server_ctx_free_routers(ctx);
        if (rc == CHIROUTER_CRITICAL_ERROR)
        {
            chilog(CRITICAL, "Error while freeing router resources");
            return CHIROUTER_CRITICAL_ERROR;
        }

        /* We only close the socket once the routers (and their ARP
         * threads, which may send frames on this socket) are gone. */
        pthread_mutex_lock(&ctx->lock_send);
        close(ctx->client_socket);
        ctx->client_socket = -1;
        pthread_mutex_unlock(&ctx->lock_send);
    }

    free(client_addr);

    return CHIROUTER_OK;
}


/* See server.h */
void chirouter_server_stop(server_ctx_t *ctx)
{
    atomic_store(&ctx->stopping, true);

    /* Wake up chirouter_server_run, which may be blocked in accept()
     * or recv(). Shutting down the server socket makes accept() fail,
     * and shutting down the client socket makes recv() return 0
     * (as if the controller had closed the connection) */
    shutdown(ctx->server_socket, SHUT_RDWR);

    pthread_mutex_lock(&ctx->lock_send);
    if (ctx->client_socket != -1)
        shutdown(ctx->client_socket, SHUT_RDWR);
    pthread_mutex_unlock(&ctx->lock_send);
}


/*
 * chirouter_server_process_messages - Processes messages received by the server
 *
 * ctx: Server context
 *
 * Note: This function does not close the client socket. That is the
 * responsibility of the caller (once it has stopped all the ARP threads)
 *
 * Returns:
 *  CHIROUTER_OK if the client closed the connection normally
 *  CHIROUTER_CRITICAL_ERROR if an error occurred
 *
 */
static int chirouter_server_process_messages(server_ctx_t *ctx)
{
    char recv_buffer[RECV_BUFFER_SIZE];
    uint8_t msg_buffer[sizeof(chirouter_msg_t)];
    chirouter_msg_t *msg = (chirouter_msg_t *) msg_buffer;
    ssize_t nbytes;
    int rc;
    bool reading_header = true;
    size_t len = 0;
    ssize_t i;
    size_t bufpos = 0;

    while (1)
    {
        nbytes = recv(ctx->client_socket, recv_buffer, sizeof(recv_buffer), 0);
        if (nbytes == 0)
        {
            chilog(DEBUG, "Mininet closed connection");
            return CHIROUTER_OK;
        }
        else if (nbytes == -1)
        {
            chilog(CRITICAL, "recv() from Mininet failed");
            return CHIROUTER_CRITICAL_ERROR;
        }

        chilog(TRACE, "recv() from Mininet (%zd bytes)", nbytes);
        chilog_hex(TRACE, recv_buffer, (size_t) nbytes);

        /* Note: a single message may be split across multiple recv() calls,
         * so bufpos, len, and reading_header must persist across them */
        i = 0;
        while (i < nbytes)
        {
            msg_buffer[bufpos++] = recv_buffer[i++];

            if (reading_header && bufpos == MSG_HDR_LEN)
            {
                /* We have a header */
                len = ntohs(msg->payload_length);
                reading_header = false;

                if (len > sizeof(chirouter_msg_t) - MSG_HDR_LEN)
                {
                    chilog(CRITICAL, "Received message with payload length %zu (maximum is %zu)",
                           len, sizeof(chirouter_msg_t) - MSG_HDR_LEN);
                    return CHIROUTER_CRITICAL_ERROR;
                }
            }

            if (!reading_header && bufpos == (MSG_HDR_LEN + len))
            {
                /* We have a complete message */
                rc = chirouter_server_process_single_message(ctx, msg);
                if (rc)
                {
                    chilog(CRITICAL, "Error while processing message.");
                    return CHIROUTER_CRITICAL_ERROR;
                }
                reading_header = true;
                bufpos = 0;
                len = 0;
            }
        }

    }
}


/*
 * chirouter_server_payload_len_is_valid - Check the payload length of a message
 *
 * Checks that the payload length of a message is valid for its type (see
 * the description of each message in server.h). For ETHERNET FRAME messages,
 * also checks that the frame length is consistent with the payload length.
 *
 * msg: Message (with a complete payload)
 *
 * payload_len: Payload length (in host byte order)
 *
 * Returns: true if the payload length is valid, false otherwise (including
 *          if the message type is unknown).
 */
static bool chirouter_server_payload_len_is_valid(const chirouter_msg_t *msg,
        uint16_t payload_len)
{
    switch (msg->type)
    {
    case MSG_TYPE_HELLO:
    case MSG_TYPE_END_CONFIG:
        return payload_len == 0;
    case MSG_TYPE_ROUTERS:
        return payload_len == MSG_ROUTERS_LEN;
    case MSG_TYPE_ROUTER:
        return payload_len > MSG_ROUTER_FIXED_LEN &&
               payload_len <= MSG_ROUTER_FIXED_LEN + MAX_ROUTER_NAMELEN;
    case MSG_TYPE_INTERFACE:
        return payload_len > MSG_INTERFACE_FIXED_LEN &&
               payload_len <= MSG_INTERFACE_FIXED_LEN + MAX_IFACE_NAMELEN;
    case MSG_TYPE_RTABLE_ENTRY:
        return payload_len == MSG_RTABLE_ENTRY_LEN;
    case MSG_TYPE_ETHERNET_FRAME:
        return payload_len >= MSG_ETHERNET_FIXED_LEN &&
               ntohs(msg->ethernet.frame_len) ==
               payload_len - MSG_ETHERNET_FIXED_LEN;
    default:
        return false;
    }
}


/*
 * chirouter_server_process_single_message - Process a single message
 *
 * ctx: Server context
 *
 * Returns: CHIROUTER_OK on success, CHIROUTER_CRITICAL_ERROR if an error
 *          happens.
 *
 */
static int chirouter_server_process_single_message(server_ctx_t *ctx,
        chirouter_msg_t *msg)
{
    int rc;
    chirouter_msg_t reply_msg;
    uint16_t payload_len = ntohs(msg->payload_length);

    if (!chirouter_server_payload_len_is_valid(msg, payload_len))
    {
        chilog(CRITICAL, "Received message of type %d with invalid payload "
               "length (%u bytes)", msg->type, payload_len);
        return CHIROUTER_CRITICAL_ERROR;
    }

    switch (msg->type)
    {
    case MSG_TYPE_HELLO:
    {
        if (ctx->state != HELLO_WAIT)
        {
            chilog(CRITICAL, "Received a HELLO message but not in the HELLO_WAIT state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        /* Send back HELLO message */
        reply_msg.type = MSG_TYPE_HELLO;
        reply_msg.subtype = FROM_ROUTER;
        reply_msg.payload_length = 0;

        rc = chirouter_server_send_msg(ctx, &reply_msg);
        if (rc)
        {
            chilog(CRITICAL, "Could not send HELLO message");
            return CHIROUTER_CRITICAL_ERROR;
        }

        ctx->state = CONFIG;
        break;
    }
    case MSG_TYPE_ROUTERS:
    {
        if (ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received a ROUTERS message but not in the CONFIG state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (ctx->routers != NULL)
        {
            chilog(CRITICAL, "Received more than one ROUTERS message");
            return CHIROUTER_CRITICAL_ERROR;
        }

        uint8_t nrouters = msg->routers.nrouters;

        if (nrouters == 0)
        {
            chilog(CRITICAL, "Received a ROUTERS message with zero routers");
            return CHIROUTER_CRITICAL_ERROR;
        }

        ctx->max_routers = nrouters;
        ctx->num_routers = 0;
        ctx->routers = xcalloc(nrouters, sizeof(chirouter_ctx_t));

        for (int i = 0; i < nrouters; i++)
        {
            chirouter_ctx_init(&ctx->routers[i]);
            ctx->routers[i].server = ctx;
        }

        break;
    }
    case MSG_TYPE_ROUTER:
    {
        if (ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received a ROUTER message but not in the CONFIG state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (msg->router.r_id != ctx->num_routers ||
                ctx->num_routers >= ctx->max_routers)
        {
            chilog(CRITICAL, "Received unexpected ROUTER message (Router ID: %d)",
                   msg->router.r_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chilog(TRACE, "Processing Router ID %d", msg->router.r_id);

        chirouter_ctx_t *r = &ctx->routers[msg->router.r_id];

        r->r_id = msg->router.r_id;

        /* The payload length has been validated, so the name fits in
         * r->name (with room for the terminating NUL) */
        size_t name_len = payload_len - MSG_ROUTER_FIXED_LEN;
        memcpy(r->name, msg->router.name, name_len);
        r->name[name_len] = '\0';

        r->max_interfaces = msg->router.num_interfaces;
        r->num_interfaces = 0;
        r->interfaces = xcalloc(r->max_interfaces,
                                sizeof(chirouter_interface_t));

        r->max_rtable_entries = msg->router.len_rtable;
        r->num_rtable_entries = 0;
        r->routing_table = xcalloc(r->max_rtable_entries,
                                   sizeof(chirouter_rtable_entry_t));

        ctx->num_routers++;

        break;
    }
    case MSG_TYPE_INTERFACE:
    {
        if (ctx->state != CONFIG)
        {
            chilog(CRITICAL, "Received an INTERFACE message but not in the CONFIG state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (msg->interface.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->interface.r_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->interface.r_id];

        if (msg->interface.iface_id != r->num_interfaces ||
                r->num_interfaces >= r->max_interfaces)
        {
            chilog(CRITICAL, "Received unexpected INTERFACE message (Interface ID: %d)",
                   msg->interface.iface_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chirouter_interface_t *iface = &r->interfaces[msg->interface.iface_id];

        chilog(TRACE, "Processing Interface ID %d in Router ID %d",
               msg->interface.iface_id,  msg->interface.r_id);

        iface->controller_iface_id = msg->interface.iface_id;

        /* The payload length has been validated, so the name fits in
         * iface->name (with room for the terminating NUL) */
        size_t name_len = payload_len - MSG_INTERFACE_FIXED_LEN;
        memcpy(iface->name, msg->interface.name, name_len);
        iface->name[name_len] = '\0';
        memcpy(iface->mac, msg->interface.hwaddr, ETHER_ADDR_LEN);
        memcpy(&iface->ip, &msg->interface.ipaddr, sizeof(struct in_addr));

        r->num_interfaces++;

        break;
    }
    case MSG_TYPE_RTABLE_ENTRY:
    {
        if (ctx->state != CONFIG)
        {
            chilog(CRITICAL,
                   "Received a ROUTING TABLE ENTRY message but not in the CONFIG state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (msg->rtable_entry.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->rtable_entry.r_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->rtable_entry.r_id];

        if (msg->rtable_entry.iface_id >= r->num_interfaces)
        {
            chilog(CRITICAL, "Received invalid Interface ID: %d",
                   msg->rtable_entry.iface_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (r->num_rtable_entries >= r->max_rtable_entries)
        {
            chilog(CRITICAL,
                   "Received ROUTING TABLE ENTRY but already have %d expected entries",
                   r->max_rtable_entries);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chilog(TRACE,
               "Processing Routing Table Entry in Router ID %d (with Interface ID %d)",
               msg->rtable_entry.r_id, msg->rtable_entry.iface_id);

        chirouter_interface_t *iface;
        chirouter_rtable_entry_t *rtentry;
        iface = &r->interfaces[msg->rtable_entry.iface_id];
        rtentry = &r->routing_table[r->num_rtable_entries];

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
        if (ctx->state != CONFIG)
        {
            chilog(CRITICAL,
                   "Received an END CONFIG message but not in the CONFIG state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (ctx->routers == NULL)
        {
            chilog(CRITICAL,
                   "Received an END CONFIG message before a ROUTERS message");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (ctx->num_routers != ctx->max_routers)
        {
            chilog(CRITICAL, "Expected %d routers but received only %d", ctx->max_routers,
                   ctx->num_routers);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chilog(INFO, "Received %i routers", ctx->num_routers);

        chilog(INFO,
               "--------------------------------------------------------------------------------");
        for (int i = 0; i < ctx->num_routers; i++)
        {
            chirouter_ctx_t *r = &ctx->routers[i];

            if (r->num_interfaces != r->max_interfaces)
            {
                chilog(CRITICAL, "Router %d: Expected %d interfaces but received only %d", i,
                       r->max_interfaces, r->num_interfaces);
                return CHIROUTER_CRITICAL_ERROR;
            }

            if (r->num_rtable_entries != r->max_rtable_entries)
            {
                chilog(CRITICAL, "Router %d: Expected %d routing table entries "
                       "but received only %d", i, r->max_rtable_entries,
                       r->num_rtable_entries);
                return CHIROUTER_CRITICAL_ERROR;
            }

            chirouter_ctx_log(&ctx->routers[i], INFO);
            rc = pthread_create(&r->arp_thread, NULL, chirouter_arp_process, r);
            if (rc != 0)
            {
                chilog(CRITICAL, "Could not create ARP thread for router %d", i);
                return CHIROUTER_CRITICAL_ERROR;
            }
            r->arp_thread_started = true;
            chilog(INFO,
                   "--------------------------------------------------------------------------------");
        }

        if (ctx->pcap)
        {
            chirouter_pcap_write_section_header(ctx);
            chirouter_pcap_write_interfaces(ctx);
        }

        ctx->state = RUNNING;
        break;
    }
    case MSG_TYPE_ETHERNET_FRAME:
    {
        if (ctx->state != RUNNING)
        {
            chilog(CRITICAL,
                   "Received an ETHERNET FRAME message but not in the RUNNING state");
            return CHIROUTER_CRITICAL_ERROR;
        }

        if (msg->ethernet.r_id >= ctx->num_routers)
        {
            chilog(CRITICAL, "Received invalid Router ID: %d", msg->ethernet.r_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chirouter_ctx_t *r = &ctx->routers[msg->ethernet.r_id];

        if (msg->ethernet.iface_id >= r->num_interfaces)
        {
            chilog(CRITICAL, "Received invalid Interface ID: %d", msg->ethernet.iface_id);
            return CHIROUTER_CRITICAL_ERROR;
        }

        chirouter_interface_t *iface = &r->interfaces[msg->ethernet.iface_id];

        rc = chirouter_server_process_ethernet_frame(r, iface,
                msg->ethernet.frame, ntohs(msg->ethernet.frame_len));
        if (rc == CHIROUTER_CRITICAL_ERROR)
        {
            chilog(CRITICAL,
                   "Error when processing Ethernet frame received from Mininet.");
            return CHIROUTER_CRITICAL_ERROR;
        }
        break;
    }
    default:
    {
        chilog(CRITICAL, "Received message with unknown type %d", msg->type);
        return CHIROUTER_CRITICAL_ERROR;
    }
    }

    return CHIROUTER_OK;
}


/*
 * chirouter_server_process_ethernet_frame - Process an inbound Ethernet frame
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
 *  CHIROUTER_OK on success
 *  CHIROUTER_CRITICAL_ERROR if a critical error happens
 *  CHIROUTER_ERROR if a non-critical error happens
 *
 */
static int chirouter_server_process_ethernet_frame(chirouter_ctx_t *ctx,
        chirouter_interface_t *iface, uint8_t *msg, size_t len)
{
    int rc;

    if (len < ETHER_HDR_LEN)
    {
        chilog(ERROR,
               "Received an Ethernet frame on interface %s that is %zu bytes long (shorter than an Ethernet header)",
               iface->name, len);
        return CHIROUTER_ERROR;
    }

    ethhdr_t *hdr = (ethhdr_t *) msg;

    bool is_broadcast = true;
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (hdr->dst[i] != 0xFF)
        {
            is_broadcast = false;
            break;
        }
    }

    bool is_multicast = (hdr->dst[0] & 0x01);

    /* If this is a multicast frame, don't process it, and only log it
     * at the TRACE level */
    if (is_multicast && !is_broadcast)
    {
        chilog(TRACE, "Received a multicast Ethernet frame. Ignoring.");
        chilog_ethernet(TRACE, msg, len, LOG_INBOUND);
        return CHIROUTER_ERROR;
    }

    chilog(DEBUG, "Received Ethernet frame on interface %s-%s", ctx->name,
           iface->name);
    chilog_ethernet(DEBUG, msg, len, LOG_INBOUND);

    /* Validate ethernet address */
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        if (hdr->dst[i] != iface->mac[i] && !is_broadcast)
        {
            chilog(WARNING,
                   "Received a non-broadcast Ethernet frame with a destination address that doesn't match the interface");
            chilog(WARNING, "Interface %s address: %02X:%02X:%02X:%02X:%02X:%02X",
                   iface->name, iface->mac[0], iface->mac[1], iface->mac[2],
                   iface->mac[3], iface->mac[4], iface->mac[5]);
            chilog(WARNING, "Ethernet destination address: %02X:%02X:%02X:%02X:%02X:%02X",
                   hdr->dst[0], hdr->dst[1], hdr->dst[2],
                   hdr->dst[3], hdr->dst[4], hdr->dst[5]);
            return CHIROUTER_ERROR;
        }
    }

    if (len < ETHER_FRAME_MIN_LEN)
    {
        chilog(TRACE,
               "Received an Ethernet frame that is %zu bytes long (shorter than the minimum size of an Ethernet frame: %i)",
               len, ETHER_FRAME_MIN_LEN);
    }

    if (len > ETHER_FRAME_MAX_LEN)
    {
        chilog(WARNING,
               "Received an Ethernet frame that is %zu bytes long (larger than the maximum size of an Ethernet frame: %i)",
               len, ETHER_FRAME_MAX_LEN);
        return CHIROUTER_ERROR;
    }

    /* Create Ethernet frame struct */
    ethernet_frame_t *frame = xcalloc(1, sizeof(ethernet_frame_t));

    frame->raw = xmalloc(len);
    memcpy(frame->raw, msg, len);
    frame->length = len;
    frame->in_interface = iface;

    if (ctx->server->pcap)
    {
        pthread_mutex_lock(&ctx->server->lock_pcap);
        chirouter_pcap_write_frame(ctx, iface, msg, len, PCAP_INBOUND);
        pthread_mutex_unlock(&ctx->server->lock_pcap);
    }

    rc = chirouter_process_ethernet_frame(ctx, frame);

    free(frame->raw);
    free(frame);

    if (rc == CHIROUTER_CRITICAL_ERROR)
    {
        chilog(CRITICAL, "Critical error while processing Ethernet frame");
        return CHIROUTER_CRITICAL_ERROR;
    }

    return CHIROUTER_OK;
}


/* See chirouter.h */
int chirouter_send_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface,
                         const uint8_t *frame, size_t frame_len)
{
    if (frame_len < ETHER_HDR_LEN)
    {
        chilog(ERROR,
               "Trying to send an Ethernet frame on interface %s that is %zu bytes long (shorter than an Ethernet header)",
               iface->name, frame_len);
        return CHIROUTER_ERROR;
    }

    if (frame_len > ETHER_FRAME_MAX_LEN)
    {
        chilog(ERROR,
               "Trying to send an Ethernet frame on interface %s that is %zu bytes long (larger than the maximum Ethernet frame size)",
               iface->name, frame_len);
        return CHIROUTER_ERROR;
    }

    chilog(DEBUG, "Sending Ethernet frame on interface %s-%s", ctx->name,
           iface->name);
    chilog_ethernet(DEBUG, frame, frame_len, LOG_OUTBOUND);

    ethhdr_t* hdr = (ethhdr_t*) frame;

    if (!ethernet_addr_is_equal(hdr->src, iface->mac))
    {
        chilog(ERROR,
               "Trying to send an Ethernet frame with source address that doesn't match that of interface %s",
               iface->name);
        return CHIROUTER_ERROR;
    }

    if (ctx->server->pcap)
    {
        pthread_mutex_lock(&ctx->server->lock_pcap);
        chirouter_pcap_write_frame(ctx, iface, frame, frame_len, PCAP_OUTBOUND);
        pthread_mutex_unlock(&ctx->server->lock_pcap);
    }

    chirouter_msg_t msg;

    msg.type = MSG_TYPE_ETHERNET_FRAME;
    msg.subtype = FROM_ROUTER;
    /* frame_len is at most ETHER_FRAME_MAX_LEN (checked above), so these
     * lengths fit in the (16-bit) length fields of the message */
    msg.payload_length = htons((uint16_t)(MSG_ETHERNET_FIXED_LEN + frame_len));
    msg.ethernet.r_id = ctx->r_id;
    msg.ethernet.iface_id = iface->controller_iface_id;
    msg.ethernet.frame_len = htons((uint16_t) frame_len);
    memcpy(msg.ethernet.frame, frame, frame_len);

    return chirouter_server_send_msg(ctx->server, &msg);
}


/*
 * chirouter_server_ctx_free_routers - Frees router resources
 *
 * ctx: Server context
 *
 * Returns: CHIROUTER_OK on success, CHIROUTER_CRITICAL_ERROR if an error
 *          happens.
 *
 */
static int chirouter_server_ctx_free_routers(server_ctx_t *ctx)
{
    int rc;

    /* All max_routers routers were initialized when the ROUTERS message
     * was received, even if we did not receive all the ROUTER messages */
    for (int i = 0; i < ctx->max_routers; i++)
    {
        rc = chirouter_ctx_destroy(&ctx->routers[i]);
        if (rc)
        {
            chilog(CRITICAL, "Could not free router resource");
            return CHIROUTER_CRITICAL_ERROR;
        }
    }

    free(ctx->routers);

    ctx->routers = NULL;
    ctx->num_routers = 0;
    ctx->max_routers = 0;

    return CHIROUTER_OK;
}


/* See server.h */
int chirouter_server_ctx_destroy(server_ctx_t *ctx)
{
    int rc;

    rc = chirouter_server_ctx_free_routers(ctx);
    if (rc)
    {
        chilog(CRITICAL, "Could not free router resources");
        return CHIROUTER_CRITICAL_ERROR;
    }

    if (ctx->server_socket != -1)
    {
        close(ctx->server_socket);
        ctx->server_socket = -1;
    }

    pthread_mutex_destroy(&ctx->lock_send);
    pthread_mutex_destroy(&ctx->lock_pcap);

    return CHIROUTER_OK;
}

