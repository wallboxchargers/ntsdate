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
#ifndef _IO_H_
#define _IO_H_

#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "nts/nts.h"


void *mdbg_malloc(size_t size);
void *mdbg_realloc(void *ptr, size_t size);

#endif
