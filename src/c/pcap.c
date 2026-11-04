/*
 *  chirouter - A simple, testable IP router
 *
 *  This module contains functions for creating a pcapng
 *  file with all the Ethernet frames that flow through the routers
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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include "server.h"
#include "chirouter.h"
#include "pcap.h"

#define PADDED_LEN(x) ((x) % 4 == 0 ? (x) : (((x) / 4) + 1) * 4)
#define PAD_LEN(x) (PADDED_LEN(x) - (x))

#define BLOCK_TYPE_SHB 0x0A0D0D0A
#define BLOCK_TYPE_IDB 0x00000001
#define BLOCK_TYPE_EPB 0x00000006

#define BYTEORDER_MAGIC 0x1A2B3C4D
#define PCAPNG_VERSION_MAJOR 1
#define PCAPNG_VERSION_MINOR 0

#define LINKTYPE_ETHERNET 1

#define OPTION_HDR_LEN 4

/* Size of the "Block Total Length" field repeated at the end of each block */
#define TRAILING_LEN 4

/* Maximum number of bytes captured from each frame */
#define SNAPLEN 65535

/* Value of the if_tsresol option: timestamps are in units of 10^-9 seconds */
#define TSRESOL_NANOSECONDS 9

/* Length of the epb_flags option value */
#define EPB_FLAGS_LEN 4

#define OPCODE_END 0
#define OPCODE_IF_NAME 2
#define OPCODE_IF_MACADDR 6
#define OPCODE_IF_TSRESOL 9
#define OPCODE_EPB_FLAGS 2


/* pcapng Section Header Block */
struct pcapng_shb
{
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    int64_t section_length;
    uint32_t block_total_length_trail;
} __attribute__((packed));

/* pcapng Interface Description Block */
struct pcapng_option
{
    uint16_t option_code;
    uint16_t option_length;
} __attribute__((packed));

/* pcapng Interface Description Block */
struct pcapng_idb
{
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
} __attribute__((packed));


/* pcapng Enhanced Packet Block */
struct pcapng_epb
{
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_plen;
    uint32_t original_plen;
} __attribute__((packed));


/* See pcap.h */
int chirouter_pcap_write_section_header(server_ctx_t *ctx)
{
    struct pcapng_shb hdr;

    hdr.block_type = BLOCK_TYPE_SHB;
    hdr.block_total_length = sizeof(hdr);
    hdr.byte_order_magic = BYTEORDER_MAGIC;
    hdr.major_version = PCAPNG_VERSION_MAJOR;
    hdr.minor_version = PCAPNG_VERSION_MINOR;
    hdr.section_length = -1;
    hdr.block_total_length_trail = sizeof(hdr);

    if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->pcap) != 1)
        return CHIROUTER_ERROR;
    else
        return CHIROUTER_OK;
}


/*
 * chirouter_pcap_write_option - Writes a pcapng option
 *
 * ctx: Server context
 *
 * option_code: Option code
 *
 * option_length: Option length
 *
 * option_value: Raw binary value of the option
 *
 * Returns: CHIROUTER_OK on success, CHIROUTER_ERROR if an error happens.
 *
 */
static int chirouter_pcap_write_option(server_ctx_t *ctx, uint16_t option_code,
                                       uint16_t option_length,
                                       const uint8_t *option_value)
{
    struct pcapng_option opt;
    size_t pad_length;
    uint32_t pad = 0;

    opt.option_code = option_code;
    opt.option_length = option_length;

    /* Write option code and length */
    if (fwrite((char *)&opt, sizeof(opt), 1, ctx->pcap) != 1)
        return CHIROUTER_ERROR;

    if (option_length > 0)
    {
        pad_length = PAD_LEN(option_length);

        assert(pad_length <= 3);

        /* Write option value */
        if (fwrite(option_value, 1, option_length, ctx->pcap) != option_length)
            return CHIROUTER_ERROR;

        if (pad_length > 0)
        {
            /* Write padding */
            if (fwrite((char *)&pad, 1, pad_length, ctx->pcap) != pad_length)
                return CHIROUTER_ERROR;
        }
    }

    return CHIROUTER_OK;
}


/* See pcap.h */
int chirouter_pcap_write_interfaces(server_ctx_t *ctx)
{
    uint32_t interface_id = 0;

    for (int i = 0; i < ctx->num_routers; i++)
    {
        chirouter_ctx_t *r = &ctx->routers[i];

        for (int i = 0; i < r->num_interfaces; i++)
        {
            chirouter_interface_t *iface = &r->interfaces[i];
            struct pcapng_idb hdr;
            char iface_name[MAX_ROUTER_NAMELEN + MAX_IFACE_NAMELEN + 2];

            snprintf(iface_name, MAX_ROUTER_NAMELEN + MAX_IFACE_NAMELEN + 2, "%s-%s",
                     r->name, iface->name);

            iface->pcap_iface_id = interface_id++;

            hdr.block_type = BLOCK_TYPE_IDB;
            hdr.link_type = LINKTYPE_ETHERNET;
            hdr.reserved = 0;
            hdr.snaplen = SNAPLEN;

            /* The interface name is at most MAX_ROUTER_NAMELEN +
             * MAX_IFACE_NAMELEN + 1 characters long */
            uint16_t name_len = (uint16_t) strlen(iface_name);

            uint32_t block_len = sizeof(hdr);
            block_len += OPTION_HDR_LEN + PADDED_LEN(name_len);
            block_len += OPTION_HDR_LEN + PADDED_LEN(ETHER_ADDR_LEN);
            block_len += OPTION_HDR_LEN + PADDED_LEN(1);
            block_len += OPTION_HDR_LEN;  // End of options
            block_len += TRAILING_LEN;
            hdr.block_total_length = block_len;

            if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->pcap) != 1)
                return CHIROUTER_ERROR;

            if (chirouter_pcap_write_option(ctx, OPCODE_IF_NAME, name_len,
                                            (const uint8_t *) iface_name))
                return CHIROUTER_ERROR;

            if (chirouter_pcap_write_option(ctx, OPCODE_IF_MACADDR,
                                            ETHER_ADDR_LEN, iface->mac))
                return CHIROUTER_ERROR;

            uint8_t tsresol = TSRESOL_NANOSECONDS;
            if (chirouter_pcap_write_option(ctx, OPCODE_IF_TSRESOL,
                                            sizeof(tsresol), &tsresol))
                return CHIROUTER_ERROR;

            if (chirouter_pcap_write_option(ctx, OPCODE_END, 0, NULL))
                return CHIROUTER_ERROR;

            if (fwrite((char *)&hdr.block_total_length,
                       sizeof(hdr.block_total_length), 1, ctx->pcap) != 1)
                return CHIROUTER_ERROR;
        }
    }

    return CHIROUTER_OK;
}

#define BILLION 1000000000L

/* See pcap.h */
int chirouter_pcap_write_frame(chirouter_ctx_t *ctx,
                               chirouter_interface_t *iface,
                               const uint8_t *msg, size_t len,
                               pcap_packet_direction_t dir)
{
    struct pcapng_epb hdr;

    /* Get nanoseconds since epoch */
    uint64_t ns;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    ns = (uint64_t) spec.tv_sec * BILLION + (uint64_t) spec.tv_nsec;

    hdr.block_type = BLOCK_TYPE_EPB;
    hdr.interface_id = iface->pcap_iface_id;
    hdr.timestamp_high = (uint32_t)(ns >> 32);
    hdr.timestamp_low = (uint32_t)(ns & 0x00000000FFFFFFFF);

    /* Frames are at most ETHER_FRAME_MAX_LEN bytes long, so their length
     * always fits in the (32-bit) length fields of the block */
    hdr.captured_plen = (uint32_t) len;
    hdr.original_plen = (uint32_t) len;

    hdr.block_total_length = sizeof(hdr);
    hdr.block_total_length += (uint32_t) len;
    hdr.block_total_length += OPTION_HDR_LEN + PADDED_LEN(EPB_FLAGS_LEN);
    hdr.block_total_length += OPTION_HDR_LEN;  // End of options
    hdr.block_total_length += TRAILING_LEN;

    if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->server->pcap) != 1)
        return CHIROUTER_ERROR;

    size_t pad_length;
    uint32_t pad = 0;

    pad_length = PAD_LEN(len);

    assert(pad_length <= 3);

    if (fwrite(msg, 1, len, ctx->server->pcap) != len)
        return CHIROUTER_ERROR;

    /* Write padding */
    if (pad_length > 0)
    {
        FILE *f = ctx->server->pcap;

        if (fwrite((char *)&pad, 1, pad_length, f) != pad_length)
            return CHIROUTER_ERROR;
    }

    /* Compute flags */
    uint32_t flags;

    switch (dir)
    {
    case PCAP_UNSPECIFIED:
        flags = 0;
        break;
    case PCAP_INBOUND:
        flags = 1;
        break;
    case PCAP_OUTBOUND:
        flags = 2;
        break;
    }

    if (chirouter_pcap_write_option(ctx->server, OPCODE_EPB_FLAGS, 4,
                                    (uint8_t*) &flags))
        return CHIROUTER_ERROR;

    if (chirouter_pcap_write_option(ctx->server, OPCODE_END, 0, NULL))
        return CHIROUTER_ERROR;

    if (fwrite((char *)&hdr.block_total_length,
               sizeof(hdr.block_total_length), 1, ctx->server->pcap) != 1)
        return CHIROUTER_ERROR;

    return CHIROUTER_OK;
}


