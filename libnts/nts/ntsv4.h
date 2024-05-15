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
#ifndef NTSV4_H
#define NTSV4_H
#include <stdint.h>
#include <time.h>

__attribute__((warn_unused_result)) ntserror requestTime(time_t * verifiedTime, uint32_t * milliseconds);
__attribute__((warn_unused_result)) ntserror getTime(char * buf, size_t maxlen);

#endif /* NTSV4_H */
