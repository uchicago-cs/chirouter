/*
 *  chirouter - A simple, testable IP router
 *
 *  Logging functions
 *
 *  see log.h for descriptions of functions, parameters, and return values.
 *
 */

/*
 *  Copyright (c) 2013-2018, The University of Chicago
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
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/ipv4.h"
#include "protocols/icmp.h"
#include "log.h"

/* chirouter_strerror uses the POSIX version of strerror_r (which returns
 * an int). glibc declares the GNU version instead (which returns a char *)
 * if _GNU_SOURCE is defined */
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
#error "chirouter_strerror requires the POSIX version of strerror_r"
#endif


/* Number of bytes printed in each line of a hexdump (see chilog_hex) */
#define HEXDUMP_BYTES_PER_LINE (16)

/* Maximum length of a line of a hexdump: the offset, plus three
 * characters per byte (and some room to spare) */
#define HEXDUMP_LINE_LEN (74)

/* Separator printed before and after the contents of a frame or message */
#define LOG_SEPARATOR \
    "   ######################################################################"

/* Logging level. Set by default to print just errors */
static loglevel_t loglevel = ERROR;


/* See log.h */
void chirouter_setloglevel(loglevel_t level)
{
    loglevel = level;
}


/* See log.h */
void chilog(loglevel_t level, const char *fmt, ...)
{
    time_t t;
    struct tm tm;
    char buf[80];
    const char *levelstr;
    va_list argptr;

    if (level > loglevel)
        return;

    t = time(NULL);
    localtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

    switch (level)
    {
    case CRITICAL:
        levelstr = "CRITIC";
        break;
    case ERROR:
        levelstr = "ERROR";
        break;
    case WARNING:
        levelstr = "WARN";
        break;
    case INFO:
        levelstr = "INFO";
        break;
    case DEBUG:
        levelstr = "DEBUG";
        break;
    case TRACE:
        levelstr = "TRACE";
        break;
    default:
        levelstr = "UNKNOWN";
        break;
    }

    flockfile(stdout);
    printf("[%s] %6s ", buf, levelstr);
    va_start(argptr, fmt);
    vprintf(fmt, argptr);
    printf("\n");
    funlockfile(stdout);
    va_end(argptr);
    fflush(stdout);
}


/* See log.h */
const char *chirouter_strerror(int errnum, char *buf, size_t buflen)
{
    if (strerror_r(errnum, buf, buflen) != 0)
        snprintf(buf, buflen, "Unknown error %d", errnum);

    return buf;
}


/* See log.h */
void chilog_ethernet(loglevel_t level, const uint8_t *frame, size_t len,
                     char prefix)
{
    if (level > loglevel)
        return;

    const ethhdr_t *header = (const ethhdr_t *) frame;
    const uint8_t *payload = ETHER_PAYLOAD_START(frame);
    size_t payload_len = len - sizeof(ethhdr_t);
    uint16_t ethertype = ntohs(header->type);

    flockfile(stdout);
    chilog(level, "%s", LOG_SEPARATOR);

    chilog(level, "%c  Src: %02X:%02X:%02X:%02X:%02X:%02X", prefix,
           header->src[0], header->src[1], header->src[2],
           header->src[3], header->src[4], header->src[5]);
    chilog(level, "%c  Dst: %02X:%02X:%02X:%02X:%02X:%02X", prefix,
           header->dst[0], header->dst[1], header->dst[2],
           header->dst[3], header->dst[4], header->dst[5]);

    const char *ethertype_str;
    switch (ethertype)
    {
    case ETHERTYPE_IP:
        ethertype_str = "IPv4";
        break;
    case ETHERTYPE_IPV6:
        ethertype_str = "IPv6";
        break;
    case ETHERTYPE_ARP:
        ethertype_str = "ARP";
        break;
    default:
        ethertype_str = "Other";
    }
    chilog(level, "%c  Ethertype: %04X (%s)", prefix, ethertype, ethertype_str);

    if (payload_len > 0)
    {
        chilog(level, "%c  Payload (%zu bytes):", prefix, payload_len);
        chilog_hex(level, payload, payload_len);
    }
    else
    {
        chilog(level, "%c  No Payload", prefix);
    }
    chilog(level, "%s", LOG_SEPARATOR);
    funlockfile(stdout);
}


/* See log.h */
void chilog_arp(loglevel_t level, const arp_packet_t *arp, char prefix)
{
    if (level > loglevel)
        return;

    flockfile(stdout);
    chilog(level, "%s", LOG_SEPARATOR);

    const char *op_str;
    if (ntohs(arp->op) == ARP_OP_REQUEST)
    {
        op_str = "Request";
    }
    else if (ntohs(arp->op) == ARP_OP_REPLY)
    {
        op_str = "Reply";
    }
    else
    {
        op_str = "Unknown";
    }

    chilog(level, "%c  ARP operation type: %04X (%s)", prefix, ntohs(arp->op),
           op_str);

    const char *hardwaretype_str;
    if (ntohs(arp->hrd) == ARP_HRD_ETHERNET)
    {
        hardwaretype_str = "Ethernet";
    }
    else
    {
        hardwaretype_str = "Other";
    }

    const char *protocoltype_str;
    switch (ntohs(arp->pro))
    {
    case ETHERTYPE_IP:
        protocoltype_str = "IPv4";
        break;
    case ETHERTYPE_IPV6:
        protocoltype_str = "IPv6";
        break;
    default:
        protocoltype_str = "Other";
    }
    chilog(level, "%c  Hardware Type: %04X (%s)   Protocol Type: %04X (%s)", prefix,
           ntohs(arp->hrd), hardwaretype_str,
           ntohs(arp->pro), protocoltype_str);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp->spa, ip_str, INET_ADDRSTRLEN);
    chilog(level, "%c  Sender: %02X:%02X:%02X:%02X:%02X:%02X  %s", prefix,
           arp->sha[0], arp->sha[1], arp->sha[2],
           arp->sha[3], arp->sha[4], arp->sha[5], ip_str);

    inet_ntop(AF_INET, &arp->tpa, ip_str, INET_ADDRSTRLEN);
    chilog(level, "%c  Target: %02X:%02X:%02X:%02X:%02X:%02X  %s", prefix,
           arp->tha[0], arp->tha[1], arp->tha[2],
           arp->tha[3], arp->tha[4], arp->tha[5], ip_str);


    chilog(level, "%s", LOG_SEPARATOR);
    funlockfile(stdout);
}


/* See log.h */
void chilog_ip(loglevel_t level, const iphdr_t *hdr, char prefix)
{
    if (level > loglevel)
        return;

    flockfile(stdout);
    chilog(level, "%s", LOG_SEPARATOR);

    const char *proto_str;
    switch (hdr->proto)
    {
    case IPPROTO_ICMP:
        proto_str = "ICMP";
        break;
    case IPPROTO_TCP:
        proto_str = "TCP";
        break;
    case IPPROTO_UDP:
        proto_str = "UDP";
        break;
    default:
        proto_str = "Other";
        break;
    }

    char ip_src_str[INET_ADDRSTRLEN], ip_dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &hdr->src, ip_src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &hdr->dst, ip_dst_str, INET_ADDRSTRLEN);
    chilog(level, "%c  Source:      %s", prefix, ip_src_str);
    chilog(level, "%c  Destination: %s", prefix, ip_dst_str);
    chilog(level, "%c  Protocol:    %02X (%s)", prefix, hdr->proto, proto_str);
    chilog(level, "%c  TTL:         %i   Total Length: %i   Checksum: %04X", prefix,
           hdr->ttl, ntohs(hdr->len), hdr->cksum);
    chilog(level, "%s", LOG_SEPARATOR);
    funlockfile(stdout);
}


/* See log.h */
void chilog_icmp(loglevel_t level, const icmp_packet_t *icmp, char prefix)
{
    if (level > loglevel)
        return;

    flockfile(stdout);
    chilog(level, "%s", LOG_SEPARATOR);

    const char *type_str;
    switch (icmp->type)
    {
    case ICMPTYPE_ECHO_REPLY:
        type_str = "Echo Reply";
        break;
    case ICMPTYPE_DEST_UNREACHABLE:
        type_str = "Destination Unreachable";
        break;
    case ICMPTYPE_ECHO_REQUEST:
        type_str = "Echo Request";
        break;
    case ICMPTYPE_TIME_EXCEEDED:
        type_str = "Time Exceeded";
        break;
    default:
        type_str = "Other";
        break;
    }

    if (icmp->type == ICMPTYPE_DEST_UNREACHABLE)
    {
        const char *code_str;
        switch (icmp->code)
        {
        case ICMPCODE_DEST_NET_UNREACHABLE:
            code_str = "Destination network unreachable";
            break;
        case ICMPCODE_DEST_HOST_UNREACHABLE:
            code_str = "Destination host unreachable";
            break;
        case ICMPCODE_DEST_PROTOCOL_UNREACHABLE:
            code_str = "Destination protocol unreachable";
            break;
        case ICMPCODE_DEST_PORT_UNREACHABLE:
            code_str = "Destination port unreachable";
            break;
        default:
            code_str = "Other";
            break;
        }
        chilog(level, "%c  Type: %02X (%s)  Code: %02X (%s)", prefix, icmp->type,
               type_str, icmp->code, code_str);
    }
    else
    {
        chilog(level, "%c  Type: %02X (%s)  Code: %02X", prefix, icmp->type, type_str,
               icmp->code);
    }

    chilog(level, "%c  Checksum: %04X", prefix, ntohs(icmp->chksum));

    switch (icmp->type)
    {
    case ICMPTYPE_ECHO_REQUEST:
    case ICMPTYPE_ECHO_REPLY:
        chilog(level, "%c  Identifier: %04X  Sequence Number: %04X", prefix,
               ntohs(icmp->echo.identifier), ntohs(icmp->echo.seq_num));
        break;
    case ICMPTYPE_DEST_UNREACHABLE:
        break;
    }

    chilog(level, "%s", LOG_SEPARATOR);
    funlockfile(stdout);
}


/* See log.h
 *
 * Based on http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data */
void chilog_hex(loglevel_t level, const void *data, size_t len)
{
    size_t i;
    char buf[24];
    char ascii[HEXDUMP_BYTES_PER_LINE + 1];
    char line[HEXDUMP_LINE_LEN];
    const uint8_t *pc = data;

    line[0] = '\0';
    ascii[0] = '\0';
    /* Process every byte in the data. */
    for (i = 0; i < len; i++)
    {
        /* Start a new line (with the line offset) */
        if ((i % HEXDUMP_BYTES_PER_LINE) == 0)
        {
            /* Just don't print ASCII for the zeroth line. */
            if (i != 0)
            {
                chilog(level, "%s  %s", line, ascii);
                line[0] = '\0';
            }

            /* Output the offset. */
            snprintf(buf, sizeof(buf), "  %04zx ", i);
            strcat(line, buf);
        }

        /* Now the hex code for the specific character. */
        snprintf(buf, sizeof(buf), " %02x", pc[i]);
        strcat(line, buf);

        /* And store a printable ASCII character for later. */
        if (isprint(pc[i]))
            ascii[i % HEXDUMP_BYTES_PER_LINE] = pc[i];
        else
            ascii[i % HEXDUMP_BYTES_PER_LINE] = '.';
        ascii[(i % HEXDUMP_BYTES_PER_LINE) + 1] = '\0';
    }

    /* Pad out the last line if it is not a full line */
    while ((i % HEXDUMP_BYTES_PER_LINE) != 0)
    {
        strcat(line, "   ");
        i++;
    }

    /* And print the final ASCII bit. */
    chilog(level, "%s  %s", line, ascii);
}
