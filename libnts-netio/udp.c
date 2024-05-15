/* libnts-netio - reference implementation of custom transport interface of libnts
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>

#include "nts/nts.h"
#include "nts-netio/stopwatch.h"

static int udpsock = -1;
static struct sockaddr udpremote_addr = {0};
static int udpzeroread = 0;

#define IP_PROTOCOL_NUMBER 0
#define RECEIVETIMEOUT_SECONDS 3
#define SENDTIMEOUT_SECONDS 1
#define SENDTIMEOUT_MICROSECONDS 100000
#define SEND_FLAGS MSG_DONTWAIT | MSG_NOSIGNAL

ntserror
PerformUdpRequestWithReply(const char * node, uint16_t port, uint8_t *ibuf, size_t len, uint8_t * obuf, size_t * outLen)
{
    int res;
    if (node == NULL || ibuf == NULL || obuf == NULL || outLen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    if (*outLen <= 0)
    {
        return NTS_BUG_TOO_SHORT_LENGTH;
    }
    stopwatch_restart(NTS_STOPWATCH_UDP, __FUNCTION__);
    stopwatch_restart(NTS_STOPWATCH_FUNCTION, __FUNCTION__);

    struct addrinfo * hostentry = NULL;
    struct addrinfo hints = {0};

    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_INET;
    char port_str[6] = {0};
    snprintf(port_str, sizeof(port_str), "%d", port);

    Log(NTS_LOG_DEBUG, LOGPREFIX "trying to look up \"%s\" port \"%s\"" LOGPOSTFIX, node, port_str);
    res = getaddrinfo(node, port_str, &hints, &hostentry);
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "getaddrinfo");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to getaddrinfo for \"%s\" port \"%s\", result %d" LOGPOSTFIX, node, port_str, res);
        freeaddrinfo(hostentry);
        return NTS_FAULT_FAILED_GETADDRINFO;
    }

    memcpy(&udpremote_addr, hostentry->ai_addr, hostentry->ai_addrlen);

    if (udpsock != -1)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "udpsock was %d and not -1 when trying to open it!" LOGPOSTFIX, udpsock);
        close(udpsock);
        udpsock = -1;
    }

    udpsock = socket(hostentry->ai_family, SOCK_DGRAM, IP_PROTOCOL_NUMBER);
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "socket");
    if(udpsock < 0)
    {
        freeaddrinfo(hostentry);
        return NTS_BUG_FAILED_SOCKET;
    }
    freeaddrinfo(hostentry);

    struct timeval tv;
    tv.tv_sec = RECEIVETIMEOUT_SECONDS;
    tv.tv_usec = 0;
    res = setsockopt(udpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "setsockopt SO_RCVTIMEO");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to set receive timeout on udpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, udpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_SETSOCKOPT;
    }
    tv.tv_sec = SENDTIMEOUT_SECONDS;
    tv.tv_usec = SENDTIMEOUT_MICROSECONDS;
    res = setsockopt(udpsock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "setsockopt SO_SNDTIMEO");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to set send timeout on udpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, udpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_SETSOCKOPT;
    }
    udpzeroread = 0;
    Log(NTS_LOG_TRACE, LOGPREFIX "udpsock \"%d\"" LOGPOSTFIX, udpsock);
    res = connect(udpsock, &udpremote_addr, sizeof(udpremote_addr));
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "connect");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to connect udpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, udpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_CONNECT;
    }

    Log(NTS_LOG_DEBUG, LOGPREFIX "connected udpsock=%d with result %d" LOGPOSTFIX, udpsock, res);
    ssize_t bytes_sent = 0;
    bytes_sent = send(udpsock, ibuf, len, SEND_FLAGS);
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "send");
    if (bytes_sent == -1)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "failed to send to udpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, udpsock, bytes_sent, errno, strerror(errno));
        *outLen = 0;
        return NTS_BUG_CANT_WRITE_UDP;
    }
    Log(NTS_LOG_TRACE, LOGPREFIX "bytes_sent %d for udp" LOGPOSTFIX, bytes_sent);

    ssize_t bytes_read = 0;
    bytes_read = recv(udpsock, obuf, *outLen, 0);
    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "recv");
    if (bytes_read == -1)
    {
        *outLen = 0;
        Log(NTS_LOG_WARN, LOGPREFIX "failed to receive data on udpsock %d, bytes_read %d and errno %d (%s)" LOGPOSTFIX, udpsock, bytes_read, errno, strerror(errno));
        return NTS_FAULT_FAILED_UDPRECV;
    }
    *outLen = (size_t)bytes_read;

    close(udpsock);
    udpsock = -1;

    stopwatch_check_millis(NTS_STOPWATCH_UDP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP, "return");
    return NTS_SUCCESS;
}

