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
#include <string.h>
#include "nts/nts_error.h"
#include "nts/io.h"
#include "nts/remote.h"
#include "nts/cookie.h"
#include "nts/nts_lengths.h"

static uint16_t ntske_port = 4460; // according to RFC8915 section 4.
static char ntske_host[MaximumFqdnLength] = {0};
static int ntske_host_set = 0;

static uint16_t nts_port = 0;
static char nts_host[MaximumFqdnLength] = {0};
static int nts_port_set = 0;
static int nts_host_set = 0;

ntserror setNtskeHost(const char * fqdn, size_t maxlen)
{
    ntserror err = NTS_SUCCESS;
    if (maxlen > MaximumFqdnLength) { return NTS_BUG_TOO_LONG_NTSKE; }

    size_t cmplen = maxlen < sizeof(ntske_host)-1 ? maxlen : sizeof(ntske_host)-1;
    if (cmplen < strnlen(ntske_host, sizeof(ntske_host)-1) || strncmp(ntske_host, fqdn, cmplen) != 0)
    {
        err = drop_cookies();
        unsetNts();
    }
    memset(ntske_host, 0, sizeof(ntske_host));
    strncpy(ntske_host, fqdn, sizeof(ntske_host)-1);

    if (strnlen(ntske_host, sizeof(ntske_host)-1) == 0)
    {
        ntske_host_set = 0;
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot set empty NTS Key Exchange host" LOGPOSTFIX);
        return NTS_BUG_NO_NTSKE_HOST;
    }
    ntske_host_set = 1;
    return err;
}

ntserror setNtsHost(const char * host, size_t maxlen)
{
    if (maxlen > MaximumFqdnLength) { return NTS_BUG_TOO_LONG_NTSHOST; }

    size_t cpylen = maxlen < sizeof(nts_host)-1 ? maxlen : sizeof(nts_host)-1;
    memset(nts_host, 0, sizeof(nts_host));
    strncpy(nts_host, host, cpylen);

    if (strnlen(nts_host, sizeof(nts_host)-1) == 0)
    {
        nts_host_set = 0;
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot set empty NTS host" LOGPOSTFIX);
        return NTS_BUG_NO_NTS_HOST;
    }
    nts_host_set = 1;
    return NTS_SUCCESS;
}

const char * getNtskeHost(void)
{
    return ntske_host;
}

const char * getNtsHost(void)
{
    return nts_host;
}

uint16_t getNtskePort(void)
{
    return ntske_port;
}

uint16_t getNtsPort(void)
{
    return nts_port;
}

void setNtsPort(uint16_t port)
{
    nts_port = port;
    nts_port_set = port > 0 ? 1 : 0;
}

void unsetNts(void)
{
    memset(nts_host, 0, sizeof(nts_host));
    nts_port = 0;
    nts_port_set = 0;
    nts_host_set = 0;
}

int isNtsSet(void)
{
    return nts_port_set == 1 && nts_host_set == 1 ? 1 : 0;
}

int isNtskeSet(void)
{
    return ntske_host_set == 1 ? 1 : 0;
}
