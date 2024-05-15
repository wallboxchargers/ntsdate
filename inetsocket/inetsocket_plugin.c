/* inetsocket - tee supplicant plugin providing TCP and UDP transport
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#include <syslog.h>

#include <tee_plugin_method.h>
#include <inetsocket_plugin.h>

#include "nts/io.h"

static TEEC_Result inetsocket_plugin_init(void)
{
    openlog("inetsocket_plugin", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_LOCAL4);
    syslog(LOG_NOTICE, "inetsocket_plugin_init, as compiled on " __DATE__ " " __TIME__ ", started");
    return TEEC_SUCCESS;
}

static TEEC_Result setupTcp(unsigned int __attribute__((unused)) sub_cmd, void *data, size_t data_len, size_t __attribute__((unused)) *out_len)
{
    PortDestMsg * msg = NULL;

    if(data_len <= (sizeof(msg->port) + sizeof(msg->msgLen)))
    {
        return TEEC_ERROR_BAD_FORMAT;
    }
    msg = (PortDestMsg *) data;

    ntserror err = SetupTcp(msg->host, msg->port);

    if (err != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "%s failed (libnts 0x%08x, %s)" LOGPOSTFIX, __FUNCTION__, err, ntsErrorAsString(err));
        return TEEC_ERROR_GENERIC;
    }

    return TEEC_SUCCESS;
}

static TEEC_Result sendTcp(unsigned int __attribute__((unused)) sub_cmd, void *data, size_t data_len, size_t *out_len)
{
    if (out_len == NULL)
    {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    ntserror err = TcpSendCallback( (char*)data, data_len, out_len );

    if (err != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "%s failed (libnts 0x%08x, %s)" LOGPOSTFIX, __FUNCTION__, err, ntsErrorAsString(err));
        return TEEC_ERROR_GENERIC;
    }

    return TEEC_SUCCESS;
}

static TEEC_Result recvTcp(unsigned int __attribute__((unused)) sub_cmd, void *data, size_t data_len, size_t *out_len)
{
    if (out_len == NULL)
    {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    ntserror err = TcpRecvCallback( (char*)data, data_len, out_len );

    if (err != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "%s failed (libnts 0x%08x, %s)" LOGPOSTFIX, __FUNCTION__, err, ntsErrorAsString(err));
        return TEEC_ERROR_GENERIC;
    }

    return TEEC_SUCCESS;
}

static TEEC_Result teardownTcp(unsigned int __attribute__((unused)) sub_cmd, void __attribute__((unused)) *data, size_t __attribute__((unused)) data_len, size_t __attribute__((unused)) *out_len)
{
    ntserror err = TeardownTcp();

    if (err != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "%s failed (libnts 0x%08x, %s)" LOGPOSTFIX, __FUNCTION__, err, ntsErrorAsString(err));
        return TEEC_ERROR_GENERIC;
    }

    return TEEC_SUCCESS;
}

static TEEC_Result setupUdp(unsigned int __attribute__((unused)) sub_cmd, void __attribute__((unused)) *data, size_t __attribute__((unused)) data_len, size_t __attribute__((unused)) *out_len)
{
    return TEEC_ERROR_NOT_SUPPORTED;
}

static TEEC_Result sendUdp(unsigned int __attribute__((unused)) sub_cmd, void __attribute__((unused)) *data, size_t __attribute__((unused)) data_len, size_t __attribute__((unused)) *out_len)
{
    return TEEC_ERROR_NOT_SUPPORTED;
}

static TEEC_Result recvUdp(unsigned int __attribute__((unused)) sub_cmd, void __attribute__((unused)) *data, size_t __attribute__((unused)) data_len, size_t __attribute__((unused)) *out_len)
{
    return TEEC_ERROR_NOT_SUPPORTED;
}

static TEEC_Result teardownUdp(unsigned int __attribute__((unused)) sub_cmd, void __attribute__((unused)) *data, size_t __attribute__((unused)) data_len, size_t __attribute__((unused)) *out_len)
{
    return TEEC_ERROR_NOT_SUPPORTED;
}

static TEEC_Result performUdpRequestWithReply(unsigned int sub_cmd, void *data, size_t data_len, size_t *out_len)
{
    PortDestMsg * msg = NULL;

    if(data_len <= (sizeof(msg->port) + sizeof(msg->msgLen)))
    {
        return TEEC_ERROR_BAD_PARAMETERS;
    }

    msg = (PortDestMsg *) data;
    Log(NTS_LOG_TRACE, LOGPREFIX "%s(%u , ..., %u, &(%u))" LOGPOSTFIX, __FUNCTION__, sub_cmd, data_len, *out_len);

    if (*out_len == 0 && sub_cmd != 0)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "out_len passed to %s is zero, using non-zero sub_cmd %u instead!" LOGPOSTFIX, __FUNCTION__, sub_cmd);
        *out_len = sub_cmd; // *out_len is zero, although it isn't in ta/io.c due to optee's design
    }

    uint8_t * udpPacketContent = (uint8_t*)(msg->host + strlen(msg->host) + 1); // +1 for trailing \0

    ntserror err = PerformUdpRequestWithReply(msg->host, msg->port, udpPacketContent, msg->msgLen, (uint8_t*)data, out_len);

    if (err != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "%s failed (libnts 0x%08x, %s)" LOGPOSTFIX, __FUNCTION__, err, ntsErrorAsString(err));
        return TEEC_ERROR_GENERIC;
    }

    return TEEC_SUCCESS;
}


static TEEC_Result getSystemTime(unsigned int __attribute__((unused)) sub_cmd, void *data, size_t data_len, size_t *out_len)
{
    if (data == NULL || out_len == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "NULLptr" LOGPOSTFIX);
        return TEEC_ERROR_EXCESS_DATA;
    }
    if (data_len < sizeof(time_t))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "insufficient buffer size: sizeof(time_t): %d, but buffer is only %d bytes" LOGPOSTFIX, sizeof(time_t), data_len);
        return TEEC_ERROR_EXCESS_DATA;
    }
    time_t ret = time(NULL);
    Log(NTS_LOG_TRACE, LOGPREFIX "getSystemTime: %ld (size %d) (sizeof time_t %d)" LOGPOSTFIX, ret, sizeof(ret), sizeof(time_t));
    memcpy(data, &ret, sizeof(ret));
    *out_len = sizeof(ret);
    return TEEC_SUCCESS;
}


static TEEC_Result inetsocket_plugin_invoke(unsigned int cmd, unsigned int sub_cmd,
                    void *data, size_t data_len,
                    size_t *out_len)
{
    /* data is used as input and output buffer. The pointer out_len is dereferenced
     * to signal the length of the output data back to the calling TA.
     */
    Log(NTS_LOG_TRACE, LOGPREFIX "invoking CMD %u %u %p %u %p\n" LOGPOSTFIX, cmd, sub_cmd, data, data_len, out_len);

    TEEC_Result res = TEEC_ERROR_NOT_SUPPORTED;

    switch (cmd) {
        case INETSOCKET_PLUGIN_CMD_SETUPTCP:
        res = setupTcp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_SENDTCP:
        res = sendTcp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_RECVTCP:
        res = recvTcp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_TEARDOWNTCP:
        res = teardownTcp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_SETUPUDP:
        res = setupUdp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_SENDUDP:
        res = sendUdp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_RECVUDP:
        res = recvUdp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_TEARDOWNUDP:
        res = teardownUdp(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_GETLINUXTIME:
        res = getSystemTime(sub_cmd, data, data_len, out_len);
        break;
    case INETSOCKET_PLUGIN_CMD_UDPREQUEST:
        res = performUdpRequestWithReply(sub_cmd, data, data_len, out_len);
        break;
    default:
        break;
    }

    Log(NTS_LOG_TRACE, LOGPREFIX "result: %d\n" LOGPOSTFIX, res);
    return res;
}

struct plugin_method plugin_method = {
    "inetsocket",
    INETSOCKET_PLUGIN_UUID,
    inetsocket_plugin_init,
    inetsocket_plugin_invoke,
};
