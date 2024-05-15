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
#ifndef NTS_UTIL_H
#define NTS_UTIL_H
#include "nts/nts_error.h"
#include <stddef.h>

ntserror Log_Hex(ntslog loglevel, const void * data, size_t len);

#endif /* NTS_UTIL_H */
