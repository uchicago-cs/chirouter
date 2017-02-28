#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "chirouter.h"

#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_ETHA_LEN 6
#define PCAP_PROTO_LEN 2

#define TCPDUMP_MAGIC 0xa1b23c4d

#define LINKTYPE_ETHERNET 1

#define min(a,b) ( (a) < (b) ? (a) : (b) )

/* pcap file header */
struct pcap_file_header {
  uint32_t   magic;         /* magic number */
  uint16_t version_major; /* version number major */
  uint16_t version_minor; /* version number minor */
  int     thiszone;      /* gmt to local correction */
  uint32_t   sigfigs;       /* accuracy of timestamps */
  uint32_t   snaplen;       /* max length saved portion of each pkt */
  uint32_t   linktype;      /* data link type (LINKTYPE_*) */
};

/* Define a new pcap record, when logging to a pcap file. */
typedef struct pcaprecord_hdr {
   uint32_t ts_sec;         /* timestamp seconds */
   uint32_t ts_nsec;        /* timestamp nanoseconds */
   uint32_t incl_len;       /* length of data saved */
   uint32_t orig_len;       /* original length of packet */
} pcaprec_hdr_t;


int chirouter_pcap_write_header(chirouter_ctx_t *ctx)
{
    struct pcap_file_header hdr;

    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.snaplen = 65535;
    hdr.sigfigs = 0;
    hdr.linktype = LINKTYPE_ETHERNET;

    if (fwrite((char *)&hdr, sizeof(hdr), 1, ctx->pcap) != 1)
        return EXIT_FAILURE;
    else
        return EXIT_SUCCESS;
}

int chirouter_pcap_write_frame(chirouter_ctx_t *ctx, chirouter_interface_t *iface, uint8_t *msg, size_t len)
{
    pcaprec_hdr_t pcap_header;
    struct timespec spec;
    int rc;

    /* TODO: Interface is not currently used. Check whether it can be included as some
     *       sort of metadata in the packet record. */

    clock_gettime(CLOCK_REALTIME, &spec);
    pcap_header.ts_sec = spec.tv_sec;
    pcap_header.ts_nsec = spec.tv_nsec;
    pcap_header.incl_len = len;
    pcap_header.orig_len = pcap_header.incl_len;

    rc = fwrite(&pcap_header, sizeof(pcaprec_hdr_t), 1, ctx->pcap);
    if (rc != 1)
        return EXIT_FAILURE;

    rc = fwrite(msg, len, 1, ctx->pcap);
    if (rc != 1)
        return EXIT_FAILURE;

    fflush(ctx->pcap); /* Flush to make sure we get the data out, in case the server is improperly shutdown. */

    return EXIT_SUCCESS;
}


