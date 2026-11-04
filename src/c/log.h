/*
 *  chirouter - A simple, testable IP router
 *
 *  Logging functions
 *
 *  Use these functions to print log messages. Each message has an
 *  associated log level:
 *
 *  CRITICAL: A critical unrecoverable error
 *  ERROR: A recoverable error
 *  WARNING: A warning
 *  INFO: High-level information about the progress of the application
 *  DEBUG: Lower-level information
 *  TRACE: Very low-level information, such as raw dumps of TCP packets.
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

#ifndef CHIROUTER_LOG_H_
#define CHIROUTER_LOG_H_

#include <stdint.h>
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/ipv4.h"
#include "protocols/icmp.h"

/* Lets GCC and Clang check the format string and arguments passed
 * to the logging functions, just like they do for printf.
 * FMT is the position of the format parameter, and ARGS is the
 * position of the first variadic argument */
#ifdef __GNUC__
#define CHIROUTER_PRINTF_FORMAT(FMT, ARGS) \
    __attribute__((format(printf, FMT, ARGS)))
#else
#define CHIROUTER_PRINTF_FORMAT(FMT, ARGS)
#endif

/* Log levels */
typedef enum
{
    QUIET    = 00,
    CRITICAL = 10,
    ERROR    = 20,
    WARNING  = 30,
    INFO     = 40,
    DEBUG    = 50,
    TRACE    = 60
} loglevel_t;

/* Log prefixes when dumping the contents of packets */
#define LOG_INBOUND ('<')
#define LOG_OUTBOUND ('>')
#define LOG_NO_DIRECTION ('|')

/*
 * chirouter_setloglevel - Sets the logging level
 *
 * When a log level is set, all messages at that level or "worse" are
 * printed. e.g., if you set the log level to WARNING, then all
 * WARNING, ERROR, and CRITICAL messages will be printed.
 *
 * level: Logging level
 *
 * Returns: Nothing.
 */
void chirouter_setloglevel(loglevel_t level);


/*
 * chilog - Print a log message
 *
 * level: Logging level of the message
 *
 * fmt: printf-style formatting string
 *
 * ...: Extra parameters if needed by fmt
 *
 * Returns: nothing.
 */
void chilog(loglevel_t level, const char *fmt, ...) CHIROUTER_PRINTF_FORMAT(2,
        3);


/* Size of the buffer to pass to chirouter_strerror */
#define STRERROR_BUF_LEN (128)

/*
 * chirouter_strerror - Returns a description of an error code
 *
 * This is a thread-safe version of strerror (which uses a static buffer).
 * For example:
 *
 *     char errbuf[STRERROR_BUF_LEN];
 *     chilog(ERROR, "bind() failed: %s",
 *            chirouter_strerror(errno, errbuf, sizeof(errbuf)));
 *
 * errnum: Error code (e.g., errno)
 *
 * buf, buflen: Buffer to store the description in
 *
 * Returns: buf (containing the description of the error)
 */
const char *chirouter_strerror(int errnum, char *buf, size_t buflen);


/*
 * chilog_ethernet - Print the header and payload of the Ethernet frame
 *
 * level: Logging level
 *
 * frame: Pointer to raw Ethernet frame
 *
 * len: Length of the complete frame (header and payload)
 *
 * prefix: Prefix added to log messages (useful to indicate the "direction"
 *         of the frame: LOG_INBOUND or LOG_OUTBOUND)
 *
 * Returns: nothing.
 */
void chilog_ethernet(loglevel_t level, const uint8_t *frame, size_t len,
                     char prefix);


/*
 * chilog_arp - Print an ARP message
 *
 * level: Logging level
 *
 * frame: Pointer to ARP message
 *
 * prefix: Prefix added to log messages (useful to indicate the "direction"
 *         of the frame: LOG_INBOUND or LOG_OUTBOUND)
 *
 * Returns: nothing.
 */
void chilog_arp(loglevel_t level, const arp_packet_t *arp, char prefix);


/*
 * chilog_ip - Print an IP header
 *
 * level: Logging level
 *
 * hdr: Pointer to the IP header
 *
 * prefix: Prefix added to log messages (useful to indicate the "direction"
 *         of the frame: LOG_INBOUND or LOG_OUTBOUND)
 *
 * Returns: nothing.
 */
void chilog_ip(loglevel_t level, const iphdr_t *hdr, char prefix);


/*
 * chilog_icmp - Print an ICMP message
 *
 * level: Logging level
 *
 * icmp: Pointer to the ICMP message
 *
 * prefix: Prefix added to log messages (useful to indicate the "direction"
 *         of the frame: LOG_INBOUND or LOG_OUTBOUND)
 *
 * Returns: nothing.
 */
void chilog_icmp(loglevel_t level, const icmp_packet_t *icmp, char prefix);

/*
 * chilog_hex - Print arbitrary data in hexdump style
 *
 * level: Logging level
 *
 * data: Pointer to the data
 *
 * len: Number of bytes to print
 *
 * Returns: nothing.
 */
void chilog_hex(loglevel_t level, const void *data, size_t len);


#endif /* CHIROUTER_LOG_H_ */
