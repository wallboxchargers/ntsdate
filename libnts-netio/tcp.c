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

static int tcpsock = -1;
static struct sockaddr tcpremote_addr = {0};
static int tcpzeroread = 0;
static const int tcpmaxzeroread = 1000;

#define IP_PROTOCOL_NUMBER 0
#define RECEIVETIMEOUT_SECONDS 3
#define SENDTIMEOUT_SECONDS 1
#define SENDTIMEOUT_MICROSECONDS 100000

ntserror
SetupTcp(const char * node, uint16_t port)
{
    int res;
    if (node == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    stopwatch_restart(NTS_STOPWATCH_TCP, __FUNCTION__);
    stopwatch_restart(NTS_STOPWATCH_FUNCTION, __FUNCTION__);

    struct addrinfo * hostentry = NULL;
    struct addrinfo hints = {0};

    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    char port_str[6] = {0};
    snprintf(port_str, sizeof(port_str), "%d", port);

    Log(NTS_LOG_DEBUG, LOGPREFIX "trying to look up \"%s\" port \"%s\"" LOGPOSTFIX, node, port_str);
    res = getaddrinfo(node, port_str, &hints, &hostentry);
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "getaddrinfo");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to getaddrinfo for \"%s\" port \"%s\", result %d" LOGPOSTFIX, node, port_str, res);
        freeaddrinfo(hostentry);
        return NTS_FAULT_FAILED_GETADDRINFO;
    }

    memcpy(&tcpremote_addr, hostentry->ai_addr, hostentry->ai_addrlen);

    if (tcpsock != -1)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "tpsock was %d and not -1 when trying to open it!" LOGPOSTFIX, tcpsock);
        close(tcpsock);
        tcpsock = -1;
    }

    tcpsock = socket(hostentry->ai_family, SOCK_STREAM, IP_PROTOCOL_NUMBER);
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "socket");
    if(tcpsock < 0)
    {
        freeaddrinfo(hostentry);
        return NTS_BUG_FAILED_SOCKET;
    }
    freeaddrinfo(hostentry);

    struct timeval tv;
    tv.tv_sec = RECEIVETIMEOUT_SECONDS;
    tv.tv_usec = 0;
    res = setsockopt(tcpsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "setsockopt SO_RCVTIMEO");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to set receive timeout on tcpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, tcpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_SETSOCKOPT;
    }
    tv.tv_sec = SENDTIMEOUT_SECONDS;
    tv.tv_usec = SENDTIMEOUT_MICROSECONDS;
    res = setsockopt(tcpsock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "setsockopt SO_SNDTIMEO");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to set send timeout on tcpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, tcpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_SETSOCKOPT;
    }
    int synRetries = 1;
    res = setsockopt(tcpsock, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries));
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "setsockopt TCP_SYNCNT");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to set SYN retries on tcpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, tcpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_SETSOCKOPT;
    }

    res = connect(tcpsock, &tcpremote_addr, sizeof(tcpremote_addr));
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "connect");
    if (res != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to connect tcpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, tcpsock, res, errno, strerror(errno));
        return NTS_BUG_FAILED_CONNECT;
    }
    
    Log(NTS_LOG_DEBUG, LOGPREFIX "connected tcpsock=%d with result %d" LOGPOSTFIX, tcpsock, res);
    tcpzeroread = 0;

    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "return");
    return NTS_SUCCESS;
}

ntserror
TcpSendCallback(char *buf, size_t sz, size_t * outLen)
{
    if (tcpsock == -1)
    {
        return NTS_BUG_NOT_INITIALIZED;
    }
    if (buf == NULL || outLen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    ssize_t bytes_sent = 0;
    stopwatch_restart(NTS_STOPWATCH_FUNCTION, __FUNCTION__);

    Log_Hex( NTS_LOG_TRACE, buf, sz );
    bytes_sent = send(tcpsock, buf, sz, 0);
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "send");
    if (bytes_sent == -1)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "failed to write to tcpsock %d with result %d and errno %d (%s)" LOGPOSTFIX, tcpsock, bytes_sent, errno, strerror(errno));
        *outLen = 0;
        return NTS_BUG_CANT_WRITE_TCP;
    }
    Log(NTS_LOG_TRACE, LOGPREFIX "bytes_sent %d for tcp" LOGPOSTFIX, bytes_sent);

    *outLen = (size_t)bytes_sent;

    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "return");
    return NTS_SUCCESS;
}

ntserror
TcpRecvCallback(char *buf, size_t sz, size_t * outLen)
{
    if (tcpsock == -1)
    {
        return NTS_BUG_NOT_INITIALIZED;
    }
    if (buf == NULL || outLen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    stopwatch_restart(NTS_STOPWATCH_FUNCTION, __FUNCTION__);

    ssize_t bytes_read = 0;
    bytes_read = recv(tcpsock, buf, sz, 0);
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "recv");
    if (bytes_read == -1)
    {
        *outLen = 0;
        Log(NTS_LOG_WARN, LOGPREFIX "failed to receive data on tcpsock %d, bytes_read %d and errno %d (%s)" LOGPOSTFIX, tcpsock, bytes_read, errno, strerror(errno));
        return NTS_FAULT_FAILED_TCPRECV;
    }
    if (bytes_read != -1)
    {
        Log_Hex( NTS_LOG_TRACE, buf, (size_t)bytes_read );
    }
    *outLen = (size_t)bytes_read;

    if (bytes_read == 0)
    {
        ++tcpzeroread;
        if (tcpzeroread >= tcpmaxzeroread)
        {
            Log(NTS_LOG_WARN, LOGPREFIX "tcpzeroread reached %d, returning NTS_FAULT_NO_DATA" LOGPOSTFIX, tcpzeroread);
            stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "NTS_FAULT_NO_DATA");
            return NTS_FAULT_NO_DATA;
        }
    }
    else
    {
        tcpzeroread = 0;
    }

    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "return");
    return NTS_SUCCESS;
}

ntserror
TeardownTcp(void)
{
    stopwatch_restart(NTS_STOPWATCH_FUNCTION, __FUNCTION__);
    if (tcpsock == -1)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "attempting to close tcpsock while it is not initialized" LOGPOSTFIX);
    }
    else
    {
        close(tcpsock);
    }
    tcpsock = -1;
    stopwatch_check_millis(NTS_STOPWATCH_TCP, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP, "return");
    return NTS_SUCCESS;
}
