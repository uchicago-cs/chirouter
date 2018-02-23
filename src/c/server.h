/*
 *  chirouter - A simple, testable IP router
 *
 *  Structs and other declarations for server.c
 *
 *  NOTE: Students should NOT use any of the data structures of functions
 *        defined in this header file. However, this file describes
 *        a network protocol used by chirouter to obtain the configuration
 *        of the routers it will manage, as well as to send/receive
 *        Ethernet frames (currently to/from a POX OpenFlow controller,
 *        although other controllers could potentially be used). We
 *        encourage you to read the protocol description, as an example
 *        of a protocol designed for this specific purpose. The server.c
 *        file also contains the code used to parse and interpret the
 *        messages in this protocol.
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


#ifndef SERVER_H_
#define SERVER_H_

#include <stdbool.h>

#include "chirouter.h"


/* The POX controller and chirouter communicate using a simple message-based
 * binary protocol. A single message has the following format:
 *
 *   ------------------------------------------------------      ---
 *  |   Type   |  Subtype  |  Payload Length  |   Payload           |
 *  | (1 byte) |  (1 byte) |    (2 bytes)     |  (N bytes)   ...    |
 *   ------------------------------------------------------      ---
 *
 *  All integers are in network order. Unless otherwise noted, all
 *  integers are unsigned.
 *
 *  The message types are described below. An informal description
 *  of the protocol can be found after the message types.
 *
 *
 *  HELLO (Type = 1)
 *  ================
 *
 *  Subtypes: 1 (From Router) and 2 (To Router)
 *
 *  Payload: None (Payload Length = 0)
 *
 *  Used to perform a simple handshake with the POX controller. When
 *  the POX controller connects to chirouter, it must send a HELLO
 *  message with Subtype = 2 (To Router). chirouter will respond
 *  with a HELLO message with Subtype = 1 (From Router)
 *
 *
 *
 *  ROUTERS (Type = 2)
 *  ==================
 *
 *  Subtype: Always 0 (None)
 *
 *  Payload:
 *
 *   ------------------------
 *  |   Number of Routers   |
 *  |       (1 byte)        |
 *   ------------------------
 *
 *  Payload Length: 1
 *
 *  This message informs chirouter of how many routers it will manage.
 *
 *
 *  ROUTER (Type = 3)
 *  =================
 *
 *  Subtype: Always 0 (None)
 *
 *  Payload:
 *
 *   -------------------------------------------------------------------------------------
 *  |   Router ID  |  Number of Interfaces  |  Routing Table Length  |       Name         |
 *  |   (1 byte)   |        (1 byte)        |       (1 byte)         |  0 < bytes <= 8 )  |
 *   -------------------------------------------------------------------------------------
 *
 *  Payload Length: 3 + len(Name)
 *
 *  This message specifies the basic parameters of a single router. It must be followed
 *  by (Number of Interfaces) INTERFACE messages and then by (Routing Table Length)
 *  ROUTING TABLE ENTRY messages.
 *
 *
 *  INTERFACE (Type = 4)
 *  ====================
 *
 *  Subtype: Always 0 (None)
 *
 *  Payload:
 *
 *   ---------------------------------------------------------------------------------------
 *  |   Router ID  |  Interface ID  |  Hardware Address  |  IPv4 Address  |      Name       |
 *  |   (1 byte)   |    (1 byte)    |      (6 bytes)     |    (4 bytes)   | 0 < bytes <= 32 |
 *   ---------------------------------------------------------------------------------------
 *
 *  Payload Length: 12 + len(Name)
 *
 *  This message specifies a single Ethernet interface in the router.
 *
 *
 *  ROUTING TABLE ENTRY (Type = 5)
 *  ==============================
 *
 *  Subtype: Always 0 (None)
 *
 *  Payload:
 *
 *   -------------------------------------------------------------------------------------------
 *  |   Router ID  |  Interface ID  |  Metric   |  Destination Network  |    Mask   |  Gateway  |
 *  |   (1 byte)   |    (1 byte)    | (2 bytes) |      (4 bytes)        | (4 bytes) | (4 bytes) |
 *   -------------------------------------------------------------------------------------------
 *
 *  Payload Length: 16
 *
 *  This message specifies a single entry in the routing table of the given router.
 *  Gateway must be set to 0 for routes that don't have a gateway.
 *
 *
 *  END CONFIG (Type = 6)
 *  =====================
 *
 *  Subtype: Always 0 (None)
 *
 *  Payload: None (Payload Length = 0)
 *
 *  Indicates that all configuration data has been sent. After this point, only
 *  ETHERNET FRAME messages can be sent.
 *
 *
 *  ETHERNET FRAME (Type = 7)
 *  =========================
 *
 *  Subtypes: 1 (From Router) and 2 (To Router)
 *
 *  Payload:
 *
 *   --------------------------------------------------------------------
 *  |   Router ID  |  Interface ID  |  Frame Length  |       Frame       |
 *  |   (1 byte)   |    (1 byte)    |    (2 bytes)   | 0 < bytes <= 1514 |
 *   --------------------------------------------------------------------
 *
 *  Payload Length: 4 + Frame Length
 *
 *  This message is used to transmit an Ethernet frame.
 *
 *  When the Subtype is 1 (From Router), it is used to inform the POX Controller
 *  that the given Ethernet frame must be sent out through the specified
 *  interface (of the specified router)
 *
 *  When the Subtype is 2 (To Router), it used by the POX Controller to inform
 *  chirouter that an Ethernet frame has been received on the specified interface
 *  (of the specified router)
 *
 *
 *  Protocol Description
 *  ====================
 *
 *  The chirouter server has three states: HELLO_WAIT, CONFIG, RUNNING
 *
 *  The server starts in the HELLO_WAIT state. Once it receives a HELLO message from
 *  the POX controller, it sends back a HELLO message and transitions to the CONFIG
 *  state.
 *
 *  The next message from the POX controller must be a ROUTERS message specifying the
 *  number N of routers that chirouter will manage. This must be followed by N router
 *  specifications using the following messages: one ROUTER, one or more INTERFACE
 *  messages, and one or more ROUTING TABLE ENTRY messages.
 *
 *  The router ID numbers must start from zero and be numbered consecutively. For
 *  a given router, the interface ID numbers must start from zero and be numbered
 *  consecutively.
 *
 *  If there are any errors in the configuration data, the server must close the
 *  connection and exit immediately.
 *
 *  After all the configuration data has been sent, the POX controller must send
 *  an END CONFIG message, and the server will transition to the RUNNING state.
 *
 *  In the RUNNING state both the server and the POX controller can send/receive
 *  ETHERNET messages. If the server receives an Ethernet frame with an invalid
 *  Router ID and/or Interface ID, it must log this occurrence and drop that frame.
 *
 *  If the POX controller closes the connection while the server is in the RUNNING
 *  state, the server must reset the chirouter data structures and return to
 *  the HELLO_WAIT state.
 *
 */


/* chirouter server messages */
struct chirouter_msg {
  uint8_t type;
  uint8_t subtype;
  uint16_t payload_length;
  union
  {
      struct
      {
          uint8_t nrouters;
      } routers;
      struct
      {
          uint8_t r_id;
          uint8_t num_interfaces;
          uint8_t len_rtable;
          char name[MAX_ROUTER_NAMELEN];
      } router;
      struct
      {
          uint8_t r_id;
          uint8_t iface_id;
          uint8_t hwaddr[ETHER_ADDR_LEN];
          uint32_t ipaddr;
          char name[MAX_IFACE_NAMELEN];
      } interface;
      struct
      {
          uint8_t r_id;
          uint8_t iface_id;
          uint16_t metric;
          uint32_t dest;
          uint32_t mask;
          uint32_t gw;
      } rtable_entry;
      struct
      {
          uint8_t r_id;
          uint8_t iface_id;
          uint16_t frame_len;
          uint8_t frame[ETHER_FRAME_MAX_LEN];
      } ethernet;
  };
} __attribute__ ((packed));
typedef struct chirouter_msg chirouter_msg_t;


/* Message types */
typedef enum
{
    MSG_TYPE_HELLO = 1,
    MSG_TYPE_ROUTERS = 2,
    MSG_TYPE_ROUTER = 3,
    MSG_TYPE_INTERFACE = 4,
    MSG_TYPE_RTABLE_ENTRY = 5,
    MSG_TYPE_END_CONFIG = 6,
    MSG_TYPE_ETHERNET_FRAME = 7
} chirouter_msg_type_t;


/* Message subtypes */
typedef enum
{
    NONE = 0,
    FROM_ROUTER = 1,
    TO_ROUTER = 2
} chirouter_msg_subtype_t;


/* Server state */
typedef enum
{
    HELLO_WAIT = 1,  // Waiting for hello from client
    CONFIG = 2,      // Receiving configuration data
    RUNNING = 3      // Able to send/receive Ethernet frames
} server_state_t;


/* The server context. Contains all the information needed
 * to run the server, as well as the router data structures. */
typedef struct server_ctx
{
    /* Server (passive) socket */
    int server_socket;

    /* Client (active) socket */
    int client_socket;

    /* Server state */
    server_state_t state;

    /* Number of routers */
    uint16_t max_routers;
    uint16_t num_routers;

    /* Pointer to array of routers. Array is guaranteed to
     * be of size "num_routers" */
    chirouter_ctx_t* routers;

    /* PCAP file to dump to */
    FILE *pcap;
} server_ctx_t;

/* See server.c for documentation */
int chirouter_server_ctx_init(server_ctx_t **ctx);
int chirouter_server_setup(server_ctx_t *ctx, char *port);
int chirouter_server_run(server_ctx_t *ctx);
int chirouter_server_ctx_destroy(server_ctx_t *ctx);

#endif /* SERVER_H_ */
