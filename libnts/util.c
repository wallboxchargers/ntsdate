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
#include "nts/util.h"
#include "nts/io.h"
#include <stdio.h>

enum { hexbufLen=1025 };
char hexbuf[hexbufLen] = {0};

#define HEXDIGITS_PER_BYTE 2
#define TERMINATING_NULL_LEN 1
#define HEXDIGITS_PER_BYTE_PLUS_TERMINATING_NULL (HEXDIGITS_PER_BYTE + TERMINATING_NULL_LEN)

ntserror Log_Hex(ntslog loglevel, const void * data, size_t len)
{
    ntserror err = NTS_SUCCESS;
    if (data == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    if (loglevel < getNtslogLevel())
    {
        return NTS_SUCCESS;
    }
    uint8_t * nextByte = (uint8_t*) data;
    while (len > 0)
    {
        size_t hexified_line = 0;
        char * buf = hexbuf;
        while (hexified_line < len && hexified_line * HEXDIGITS_PER_BYTE + HEXDIGITS_PER_BYTE_PLUS_TERMINATING_NULL <= sizeof(hexbuf))
        {
            int nPrintedChars = snprintf(buf, HEXDIGITS_PER_BYTE_PLUS_TERMINATING_NULL, "%02X", *nextByte);
            if (nPrintedChars < 0)
            {
                Log( NTS_LOG_ERROR, LOGPREFIX "snprintf(..., %u, \"%%02X\", ...) returned %d < 0 indicating an output error" LOGPOSTFIX, HEXDIGITS_PER_BYTE_PLUS_TERMINATING_NULL, nPrintedChars );
                return NTS_BUG_CANT_OUTPUT;
            }
            else if (nPrintedChars < HEXDIGITS_PER_BYTE)
            {
                Log( NTS_LOG_ERROR, LOGPREFIX "unexpected return value %d of snprintf(..., %u, \"%%02X\", *nextByte)" LOGPOSTFIX, nPrintedChars, HEXDIGITS_PER_BYTE_PLUS_TERMINATING_NULL );
                return NTS_BUG_UNKNOWN;
            }
            else if (nPrintedChars == HEXDIGITS_PER_BYTE)
            {
                ++hexified_line;
                ++nextByte;
                buf += HEXDIGITS_PER_BYTE;
            }
            else // return values of snprintf equal or greater than its second argument indicate truncation
            {
                break; // end of hexbuf / maximum line length reached
            }
        }
        Log(loglevel, "%s", hexbuf);
        len -= hexified_line; // no integer underflow due to hexified_line < len before loop and only single ++hexified_line in loop
    }

    return err;
}
