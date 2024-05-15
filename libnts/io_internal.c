/* libnts - a minimalistic RFC8915 implementation supporting custom transport
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#include "nts/nts_error.h"
#include "nts/io.h"
#include "nts/io_internal.h"

#define WOLFCALLBACK_FAILED -1

int TcpRecvWolfCallback(WOLFSSL __attribute__((unused)) *ssl, char *buf, int sz, void __attribute__((unused)) *ctx)
{
    if (sz < 0)
    {
        Log( NTS_LOG_ERROR, LOGPREFIX "negative size encountered: %d" LOGPOSTFIX, sz);
        return WOLFCALLBACK_FAILED;
    }
    size_t outLen = (size_t)sz;
    ntserror ret = TcpRecvCallback(buf, (size_t)sz, &outLen);
    if (outLen > INT_MAX)
    {
        Log( NTS_LOG_ERROR, LOGPREFIX "too large output length encountered: %u" LOGPOSTFIX, outLen );
        return WOLFCALLBACK_FAILED;
    }
    return (ret == NTS_SUCCESS) ? (int)outLen : WOLFCALLBACK_FAILED ;
}

int TcpSendWolfCallback(WOLFSSL __attribute__((unused)) *ssl, char *buf, int sz, void __attribute__((unused)) *ctx)
{
    if (sz < 0)
    {
        Log( NTS_LOG_ERROR, LOGPREFIX "negative size encountered: %d" LOGPOSTFIX, sz);
        return WOLFCALLBACK_FAILED;
    }
    size_t outLen = (size_t)sz;
    ntserror ret = TcpSendCallback(buf, (size_t)sz, &outLen);
    if (outLen > INT_MAX)
    {
        Log( NTS_LOG_ERROR, LOGPREFIX "too large output length encountered: %u" LOGPOSTFIX, outLen );
        return WOLFCALLBACK_FAILED;
    }
    return (ret == NTS_SUCCESS) ? (int)outLen : WOLFCALLBACK_FAILED ;
}
