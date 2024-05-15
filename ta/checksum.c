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
#include <stdint.h>
#include "checksum.h"
#include "adler32.h"
extern uint8_t __text_start;
extern uint8_t __text_end;
extern uint8_t __rodata_start;
extern uint8_t __rodata_end;

uint32_t calculateTaChecksum(void)
{
    static uint32_t seed = 0xD1EE1C42;
    uint32_t checksum = seed;
    checksum = adler32(checksum, &__text_start, (size_t)(&__text_end - &__text_start));
    checksum = adler32(checksum, &__rodata_start, (size_t)(&__rodata_end - &__rodata_start));
    return checksum;
}

