#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include "server.h"
#include "chirouter.h"
#include "pcap.h"

#define PADDED_LEN(x) (x%4==0 ? x : ((x/4)+1)*4)
#define PAD_LEN(x) (PADDED_LEN(x) - x)

#define BLOCK_TYPE_SHB 0x0A0D0D0A
#define BLOCK_TYPE_IDB 0x00000001
#define BLOCK_TYPE_EPB 0x00000006

#define BYTEORDER_MAGIC 0x1A2B3C4D
#define PCAPNG_VERSION_MAJOR 1
#define PCAPNG_VERSION_MINOR 0

#define LINKTYPE_ETHERNET 1

#define OPTION_HDR_LEN 4

#define OPCODE_END 0
#define OPCODE_IF_NAME 2
#define OPCODE_IF_MACADDR 6
#define OPCODE_IF_TSRESOL 9
#define OPCODE_EPB_FLAGS 2

#define min(a,b) ( (a) < (b) ? (a) : (b) )

/* pcapng Section Header Block */
struct pcapng_shb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    int64_t section_length;
    uint32_t block_total_length_trail;
} __attribute__((packed));

/* pcapng Interface Description Block */
struct pcapng_option {
    uint16_t option_code;
    uint16_t option_length;
} __attribute__((packed));

/* pcapng Interface Description Block */
struct pcapng_idb {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
} __attribute__((packed));


/* pcapng Enhanced Packet Block */
struct pcapng_epb {
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
        return EXIT_FAILURE;
    else
        return EXIT_SUCCESS;
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
 * Returns: 0 on success, -1 if an error happens.
 *
 */
int chirouter_pcap_write_option(server_ctx_t *ctx, uint16_t option_code, uint16_t option_length, uint8_t *option_value)
{
    struct pcapng_option opt;
    uint16_t pad_length;
    uint32_t pad = 0;

    opt.option_code = option_code;
    opt.option_length = option_length;

    /* Write option code and length */
    if (fwrite((char *)&opt, sizeof(opt), 1, ctx->pcap) != 1)
        return EXIT_FAILURE;

    if(option_length > 0)
    {
        pad_length = PAD_LEN(option_length);

        assert(pad_length >= 0 && pad_length <= 3);

        /* Write option value */
        if (fwrite(option_value, 1, option_length, ctx->pcap) != option_length)
            return EXIT_FAILURE;

        if(pad_length > 0)
        {
            /* Write padding */
            if (fwrite((char *)&pad, 1, pad_length, ctx->pcap) != pad_length)
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}


/* See pcap.h */
int chirouter_pcap_write_interfaces(server_ctx_t *ctx)
{
    uint32_t interface_id = 0;

    for(int i=0; i < ctx->num_routers; i++)
    {
        chirouter_ctx_t *r = &ctx->routers[i];

        for(int i=0; i < r->num_interfaces; i++)
        {
            chirouter_interface_t *iface = &r->interfaces[i];
            struct pcapng_idb hdr;
            char iface_name[MAX_IFACE_NAMELEN + 1];

            snprintf(iface_name, MAX_IFACE_NAMELEN + 1, "%s-%s", r->name, iface->name);

            iface->pcap_iface_id = interface_id++;

            hdr.block_type = BLOCK_TYPE_IDB;
            hdr.link_type = LINKTYPE_ETHERNET;
            hdr.reserved = 0;
            hdr.snaplen = 65535;

            hdr.block_total_length = sizeof(hdr);
            hdr.block_total_length += OPTION_HDR_LEN + PADDED_LEN(strlen(iface_name));
            hdr.block_total_length += OPTION_HDR_LEN + PADDED_LEN(ETHER_ADDR_LEN);
            hdr.block_total_length += OPTION_HDR_LEN + PADDED_LEN(1);
            hdr.block_total_length += OPTION_HDR_LEN; /* End of options */
            hdr.block_total_length += 4; /* Trailing length */

            if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->pcap) != 1)
                return EXIT_FAILURE;

            if(chirouter_pcap_write_option(ctx, OPCODE_IF_NAME, strlen(iface_name), (uint8_t *) iface_name))
                return EXIT_FAILURE;

            if(chirouter_pcap_write_option(ctx, OPCODE_IF_MACADDR, ETHER_ADDR_LEN, iface->mac))
                return EXIT_FAILURE;

            uint8_t tsresol = 9;
            if(chirouter_pcap_write_option(ctx, OPCODE_IF_TSRESOL, 1, &tsresol))
                return EXIT_FAILURE;

            if(chirouter_pcap_write_option(ctx, OPCODE_END, 0, NULL))
                return EXIT_FAILURE;

            if (fwrite((char *)&hdr.block_total_length, sizeof(hdr.block_total_length), 1, ctx->pcap) != 1)
                return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

#define BILLION 1000000000L

int chirouter_pcap_write_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len, pcap_packet_direction_t dir)
{
    struct pcapng_epb hdr;

    /* Get nanoseconds since epoch */
    uint64_t ns;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    ns = (uint64_t) spec.tv_sec * BILLION + (uint64_t) spec.tv_nsec;

    hdr.block_type = BLOCK_TYPE_EPB;
    hdr.interface_id = iface->pcap_iface_id;
    hdr.timestamp_high = ns >> 32;
    hdr.timestamp_low = ns & 0x00000000FFFFFFFF;
    hdr.captured_plen = len;
    hdr.original_plen = len;

    hdr.block_total_length = sizeof(hdr);
    hdr.block_total_length += len;
    hdr.block_total_length += OPTION_HDR_LEN + PADDED_LEN(4); /* Flags */
    hdr.block_total_length += OPTION_HDR_LEN; /* End of options */
    hdr.block_total_length += 4; /* Trailing length */

    if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->server->pcap) != 1)
        return EXIT_FAILURE;

    uint32_t pad_length;
    uint32_t pad = 0;

    pad_length = PAD_LEN(len);

    assert(pad_length >= 0 && pad_length <= 3);

    if (fwrite(msg, 1, len, ctx->server->pcap) != len)
        return EXIT_FAILURE;

    /* Write padding */
    if(pad_length > 0)
    {
        if (fwrite((char *)&pad, 1, pad_length, ctx->server->pcap) != pad_length)
            return EXIT_FAILURE;
    }

    /* Compute flags */
    uint32_t flags;

    switch(dir)
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

    if(chirouter_pcap_write_option(ctx->server, OPCODE_EPB_FLAGS, 4, (uint8_t*) &flags))
        return EXIT_FAILURE;

    if(chirouter_pcap_write_option(ctx->server, OPCODE_END, 0, NULL))
        return EXIT_FAILURE;

    if (fwrite((char *)&hdr.block_total_length, sizeof(hdr.block_total_length), 1, ctx->server->pcap) != 1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}


