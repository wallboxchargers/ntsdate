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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nts/cookie.h"
#include "nts/nts_error.h"
#include "nts/io.h"
#include "nts/util.h"

typedef struct cookie {
    uint16_t len;
    char * buf;
    struct cookie * prev;
    struct cookie * next;
} Cookie;

typedef struct {
    int nCookies;
    Cookie * first;
    Cookie * last;
} CookieList;

CookieList cookieList = {0};

ntserror push_cookie(const uint8_t * buf, uint16_t len)
{
    Cookie * newCookie = NULL;
    if((newCookie = malloc(sizeof(Cookie))) == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot create new cookie - out of memory" LOGPOSTFIX);
        return NTS_BUG_CANT_MALLOC;
    }

    memset(newCookie, 0, sizeof(Cookie));
    newCookie->len = len;

    if((newCookie->buf = malloc(len)) == NULL)
    {
        free(newCookie);

        Log(NTS_LOG_ERROR, LOGPREFIX "cannot create new cookie buffer - out of memory" LOGPOSTFIX);
        return NTS_BUG_CANT_MALLOC;
    }
    memcpy(newCookie->buf, buf, len);

    newCookie->prev = cookieList.last;
    newCookie->next = NULL;
    if (cookieList.last != NULL)
    {
        cookieList.last->next = newCookie;
    }
    cookieList.last = newCookie;
    ++cookieList.nCookies;

    if (cookieList.first == NULL)
    {
        cookieList.first = newCookie;
    }

    return NTS_SUCCESS;
}

ntserror popl_cookie(uint8_t * buf, uint16_t maxlen, size_t * lenOut)
{
    Cookie * retCookie = NULL;

    if(lenOut == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot retrieve cookie - buffer length pointer is NULL" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    if((retCookie = cookieList.first) == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot retrieve cookie - first cookie in list is empty" LOGPOSTFIX);
        return NTS_BUG_NULL_FIRSTCOOKIE;
    }

    Log_Hex( NTS_LOG_TRACE, &(cookieList.first), 4 );
    Log_Hex( NTS_LOG_TRACE, &(cookieList.last), 4 );
    Log_Hex( NTS_LOG_TRACE, &(cookieList.first->buf), 4 );
    Log_Hex( NTS_LOG_TRACE, &(cookieList.first->prev), 4 );
    Log_Hex( NTS_LOG_TRACE, &(cookieList.first->next), 4 );
    Log( NTS_LOG_TRACE, LOGPREFIX "retCookie->len %d, maxlen %d, cookieList.nCookies %d" LOGPOSTFIX, retCookie->len, maxlen, cookieList.nCookies );

    size_t len = retCookie->len;
    if (len > maxlen)
    {
        *lenOut = len;
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot retrieve cookie - length (%d) exceeds maximum (%d)" LOGPOSTFIX, len, maxlen);
        return NTS_BUG_TOO_LONG_COOKIE;
    }

    memcpy(buf, retCookie->buf, len);

    cookieList.first = retCookie->next;
    if (cookieList.first)
    {
        cookieList.first->prev = NULL;
    }
    else
    {
        cookieList.last = NULL;
    }
    --cookieList.nCookies;

    /* FIXME: TODO: automatically rerun NTS KE? */
    if(cookieList.nCookies < 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot retrieve cookie - no cookies left" LOGPOSTFIX);
        return NTS_BUG_NO_COOKIESLEFT;
    }

    free(retCookie->buf);
    retCookie->len = 0;
    retCookie->next = NULL;
    free(retCookie);

    *lenOut = len;
    return NTS_SUCCESS;
}

int count_cookies(void)
{
    return cookieList.nCookies;
}

ntserror drop_cookies(void)
{
    Log(NTS_LOG_VERBOSE, LOGPREFIX "dropping %d cookies." LOGPOSTFIX, count_cookies());
    uint8_t buf[1280] = {0};
    size_t cookielen;
    ntserror err = NTS_SUCCESS;
    while (count_cookies() > 0)
    {
        if((err = popl_cookie(buf, sizeof(buf), &cookielen)) != NTS_SUCCESS)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot drop cookie - popl_cookie failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
            return NTS_BUG_CANT_POPL_COOKIE;
        }

        if(cookielen <= 0)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot drop cookie - length (%d) too short" LOGPOSTFIX, cookielen);
            return NTS_BUG_TOO_SHORT_COOKIE;
        }
    }
    return NTS_SUCCESS;
}
