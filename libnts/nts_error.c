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

const char * ntsErrorAsString(ntserror err)
{
    switch(err)
    {
        NTS_ERRORS(WRITTEN_AS_CASE)
        default:
            return "NTS_UNKNOWN_ERROR";
    }
    return "NTS_BAD_ERROR";
}

const char * ntsLoglevelAsString(ntslog sev)
{
    switch(sev)
    {
        NTS_LOGLEVELS(WRITTEN_AS_CASE)
        default:
            return "NTS_LOG_UNKNOWN";
    }
    return "NTS_LOG_BAD";
}
