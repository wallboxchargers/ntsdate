/* ntsdate - perform a NTS-KE and query once an NTP server supporting NTS using libnts
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <printk.h>
#include <trace.h>

#include <inetsocket_plugin.h>
#include "plugin/syslog_plugin.h"
#include <syslog.h>

#include "nts/nts.h"
#include "nts-log2syslog/syslog.h"
#include <string.h>

#include "time.h"

ntserror
SetupTcp(const char * dest_str, uint16_t port)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    char iobuf[iobufLen] = {0};

    PortDestMsg * msg = (PortDestMsg *) iobuf;
    msg->port = port;
    strncpy(msg->host, dest_str, sizeof(msg->host)-1);

    const size_t inbufLen = sizeof(msg->port) + sizeof(msg->msgLen) + strnlen(msg->host, sizeof(msg->host)-1) + 1; // +1 for trailing \0
    size_t outbufLen = 0;

    Log_Hex( NTS_LOG_TRACE, iobuf, inbufLen );
    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_SETUPTCP, 0 /* subcommand */, iobuf, inbufLen, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_BUG_FAILED_PLUGIN_SETUPTCP;
    }

    return NTS_SUCCESS;
}

ntserror
TcpRecvCallback(char *buf, size_t sz, size_t * outLen)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    size_t outbufLen = 0;

    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_RECVTCP, 0 /* subcommand */, buf, sz, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_BUG_FAILED_PLUGIN_RECVTCP;
    }

    if(outLen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }

    *outLen = outbufLen;

    return NTS_SUCCESS;
}

ntserror
TcpSendCallback(char *buf, size_t sz, size_t * outLen)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    size_t outbufLen = 0;

    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_SENDTCP, 0 /* subcommand */, buf, sz, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_BUG_FAILED_PLUGIN_SENDTCP;
    }

    if(outLen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }

    *outLen = outbufLen;

    return NTS_SUCCESS;
}

ntserror
TeardownTcp(void)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    char iobuf[iobufLen] = {0};
    const size_t inbufLen = iobufLen;
    size_t outbufLen = 0;

    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_TEARDOWNTCP, 0 /* subcommand */, iobuf, inbufLen, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_BUG_FAILED_TCPTEARDOWN;
    }

    return NTS_SUCCESS;
}

ntserror
PerformUdpRequestWithReply(const char * host, uint16_t port, uint8_t *ibuf, size_t len, uint8_t *obuf, size_t * maxlen)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    if(maxlen == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }

    char iobuf[iobufLen] = {0};

    PortDestMsg * msg = (PortDestMsg *) iobuf;
    msg->port = port;

    if(len == 0)
    {
        return NTS_BUG_TOO_SHORT_LENGTH;
    }

    if(len > UINT16_MAX)
    {
        return NTS_BUG_TOO_LARGE_UINT16;
    }

    msg->msgLen = (uint16_t)len;
    strncpy(msg->host, host, sizeof(msg->host)-1); // -1 for enforcing trailing \0

    size_t inbufLen = sizeof(msg->port) + sizeof(msg->msgLen) + strnlen(msg->host, sizeof(msg->host)-1) + 1; // +1 for trailing \0
    size_t outbufLen = 0;

    char * ntspacket = (msg->host+strnlen(msg->host, sizeof(msg->host)-1)+1);

    if((inbufLen + len) > iobufLen)
    {
        return NTS_BUG_TOO_LONG;
    }

    if(ibuf == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }

    memcpy(ntspacket, ibuf, len);
    inbufLen += len;

    Log_Hex( NTS_LOG_TRACE, iobuf, inbufLen );

    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_UDPREQUEST, iobufLen /* subcommand abused as workaround */, iobuf, inbufLen, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_FAULT_FAILED_UDPREQUEST;
    }

    Log_Hex( NTS_LOG_TRACE, iobuf, outbufLen );

    if(outbufLen > *maxlen)
    {
        return NTS_BUG_TOO_SHORT_UDPBUFFER;
    }

    if(obuf == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }

    memcpy(obuf, iobuf, outbufLen);

    *maxlen = outbufLen;
    return NTS_SUCCESS;
}

void __vsyslog_chk(int priority, int __attribute__((unused)) flag, const char * format, va_list ap)
{
    TEE_UUID syslog_uuid = SYSLOG_PLUGIN_UUID;
    TEE_Result syslog_res = TEE_SUCCESS;
    char syslog_buf[MAX_PRINT_SIZE * 4] = {0};
    size_t syslog_len = 0;
    int res = 0;

    if (format == NULL)
    {
        return;
    }

    res = vsnprintk(syslog_buf, sizeof(syslog_buf), format, ap);
    if (res < 0)
    {
        EMSG("vsnprintk failed, returns %d; printing to console", res);
        trace_vprintf(__func__, __LINE__, TRACE_ERROR, true, format, ap);
        return;
    }
    syslog_len = (size_t)res;

    // in case buffer was too small, sanitize end; requirement: sizeof(syslog_buf) >= 2.
    if (syslog_len >= (sizeof(syslog_buf) - 1))
    {
        syslog_len = sizeof(syslog_buf) - 2;
    }
    syslog_buf[syslog_len] = '\n';

    // trim trailing newlines but keep a message consisting in nothing except a single '\n' intact.
    while (syslog_len > 0 && syslog_buf[syslog_len] == '\n')
    {
        syslog_len--;
    }
    syslog_len++;

    syslog_buf[syslog_len++] = '\0';
    // syslog_len is finally the size of message including the terminating 0


    syslog_res = tee_invoke_supp_plugin(&syslog_uuid, TO_SYSLOG_CMD, (uint32_t)priority, syslog_buf, syslog_len, NULL);
    // Print to console if invoking syslog plugin failed
    if(syslog_res != TEE_SUCCESS)
    {
        EMSG("syslog plugin failed with code 0x%x, printing to console", syslog_res);
        trace_vprintf(__func__, __LINE__, TRACE_ERROR, true, format, ap);
    }
}


int
getRandom(uint8_t * buf, size_t len)
{
    TEE_GenerateRandom(buf, len);
    if (len > INT_MAX)
    {
        return -1;
    }
    return (int)len;
}

int
getrandom(void * buf, size_t len, unsigned int __attribute__((unused)) flags)
{
    TEE_GenerateRandom(buf, len);
    if (len > INT_MAX)
    {
        return -1;
    }
    return (int)len;
}

uint32_t
rand_gen(void)
{
    uint32_t rnd;
    TEE_GenerateRandom(&rnd, sizeof(rnd));
    return rnd;
}

time_t time(time_t *tloc)
{
    TEE_UUID inetsocket_uuid = INETSOCKET_PLUGIN_UUID;
    TEE_Result res;

    time_t linuxtime = 0;
    char * iobuf = (char*)&linuxtime;
    const size_t inbufLen = sizeof(linuxtime);
    size_t outbufLen = 0;

    res = tee_invoke_supp_plugin(&inetsocket_uuid, INETSOCKET_PLUGIN_CMD_GETLINUXTIME, 0 /* subcommand */, iobuf, inbufLen, &outbufLen);
    if(res != TEE_SUCCESS)
    {
        return NTS_BUG_FAILED_GETLINUXTIME;
    }

    Log_Hex( NTS_LOG_TRACE, iobuf, outbufLen );

    if (tloc != NULL)
    {
        *tloc = linuxtime;
    }

    return linuxtime;
}

