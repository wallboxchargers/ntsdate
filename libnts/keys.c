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
#include "nts/nts_lengths.h"
#include "nts/keys.h"

// TODO/FIXME: in general, combining key storage, storage size and thereof used size is likely better than using three independent variables.
// Then, setKey could rigorously check and would not need the assumption, that the first argument points to a sufficiently large memory block.
// As long as only the following two arrays are used as arguments to the private setKey function, this assumption is however valid.
static uint8_t C2S[AeadAesSivCmac256KeyLength] = {0};
static uint8_t S2C[AeadAesSivCmac256KeyLength] = {0};
static uint16_t C2S_length = 0;
static uint16_t S2C_length = 0;

/* private function declarations */
static ntserror setKey(uint8_t * key, uint16_t * len, const uint8_t * newkey, uint16_t newlen);


ntserror setC2S(const uint8_t * newkey, uint16_t len)
{
    return setKey(C2S, &C2S_length, newkey, len);
}
ntserror setS2C(const uint8_t * newkey, uint16_t len)
{
    return setKey(S2C, &S2C_length, newkey, len);
}

static ntserror setKey(uint8_t * key, uint16_t * len, const uint8_t * newkey, uint16_t newlen)
{
    if (key == NULL || len == NULL || newkey == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    if (newlen != AeadAesSivCmac256KeyLength) // it is implied here that key must provide at least AeadAesSivCmac256KeyLength bytes storage
    {
        return NTS_BUG_BAD_KEYLENGTH;
    }
    memset(key, 0, *len);
    memcpy(key, newkey, newlen);
    *len = newlen;

    return NTS_SUCCESS;
}


const uint8_t * getS2C(void)
{
    return S2C;
}

const uint8_t * getC2S(void)
{
    return C2S;
}

uint16_t getS2CLength(void)
{
    return S2C_length;
}

uint16_t getC2SLength(void)
{
    return C2S_length;
}
