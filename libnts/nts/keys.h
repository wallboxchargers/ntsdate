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
#ifndef NTS_KEYS_H
#define NTS_KEYS_H

#include <stdint.h>
#include "nts/nts_error.h"

ntserror setC2S(const uint8_t * newkey, uint16_t len);
ntserror setS2C(const uint8_t * newkey, uint16_t len);

const uint8_t * getS2C(void);
const uint8_t * getC2S(void);

uint16_t getS2CLength(void);
uint16_t getC2SLength(void);

#endif /* NTS_KEYS_H*/
