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
#include <stdio.h>
#include <stdlib.h>

#include "nts/user_settings.h"
#include <wolfssl/ssl.h>

#include "nts/nts_error.h"
#include "nts/io.h"
#include "nts/hashes.h"
#include "nts/util.h"

#define MAX_CHAIN_LENGTH 5
uint8_t shaSums[MAX_CHAIN_LENGTH][SHA256_DIGEST_SIZE];
uint8_t nEntries = 0;

void drop_hashes(void)
{
    for (int idx = 0; idx < MAX_CHAIN_LENGTH; ++idx)
    {
        memset(shaSums[idx], 0, SHA256_DIGEST_SIZE * sizeof(uint8_t));
    }
    nEntries = 0;
}

ntserror store_hash(size_t idx, const uint8_t *der, size_t derLength)
{
    if(der == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash - DER is null" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    if(derLength == 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash - DER length is %d" LOGPOSTFIX, derLength);
        return NTS_BUG_TOO_SHORT_DER;
    }

    if(idx >= MAX_CHAIN_LENGTH)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash - index (%d) exceeds maximum (%d)" LOGPOSTFIX, idx, MAX_CHAIN_LENGTH);
        return NTS_BUG_TOO_SHORT_HASHSTORE;
    }
    ++nEntries;

    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, der, derLength);
    wc_Sha256Final(&sha, shaSums[idx]);

    Log( NTS_LOG_VERBOSE, LOGPREFIX "SHA256 Fingerprint of complete certificate follows:" LOGPOSTFIX );
    Log_Hex( NTS_LOG_VERBOSE, shaSums[idx], SHA256_DIGEST_SIZE );

    return NTS_SUCCESS;
}

ntserror hash_as_hex_to_buffer(size_t idx, char * buf, size_t maxlen, size_t * outlen)
{
    if((buf == NULL) || (outlen == NULL))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash in hex buffer - buffer pointer or buffer length pointer is null" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    if(maxlen < (2 * SHA256_DIGEST_SIZE))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash in hex buffer - length (%d) too short for digest (%d)" LOGPOSTFIX,
                maxlen, (2 * SHA256_DIGEST_SIZE));
        return NTS_BUG_TOO_SHORT;
    }

    if(idx >= nEntries)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash in hex buffer - index (%d) exceeds maximum (%d)" LOGPOSTFIX,
                idx, nEntries);
        return NTS_BUG_OUTOFBOUND_INDEX;
    }

    *outlen = 0;
    for (int64_t __i = 0; __i < SHA256_DIGEST_SIZE ; ++__i)
    {
        if(snprintf(buf, 3, "%02X", ((shaSums[idx])[__i]&0xff)) != 2)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hash in hex buffer - byte could not be converted to hex" LOGPOSTFIX);
            return NTS_BUG_CANT_SNPRINTF;
        }

        buf += 2;
        *outlen += 2;
    }

    return NTS_SUCCESS;
}

int count_hashes(void)
{
    return nEntries;
}

