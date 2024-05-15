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
#include "nts/user_settings.h"
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <string.h>

#include "nts/nts.h"
#include "nts/ntske.h"
#include "nts/ntsv4_internal.h"

// https://www.rfc-editor.org/rfc/rfc5297.html#section-3 says: if the nonce is random, it SHOULD be at least 128 bits
enum { NonceLength = 16 };

enum {
    UniqueIdentifierExtensionField = 0x0104,
    NtsCookieExtensionField = 0x0204,
    NtsCookiePlaceholderExtensionField = 0x0304,
    NtsAuthenticatorAndEncryptedExtensionField = 0x0404,
} NtsExtensionFieldTypes;

const char * const NtsExtensionFieldTypeStrings[4] = {
    "UniqueIdentifierExtensionField",
    "NtsCookieExtensionField",
    "NtsCookiePlaceholderExtensionField",
    "NtsAuthenticatorAndEncryptedExtensionField",
};

/* RFC8915: When cookies adhere to the format recommended in Section 6 and the AEAD in use is the mandatory-to-implement AEAD_AES_SIV_CMAC_256, senders can include a cookie and seven placeholders and still have packet size fall comfortably below 1280 octets if no non-NTS-related extensions are used; 1280 octets is the minimum prescribed MTU for IPv6 and is generally safe for avoiding IPv4 fragmentation. */
enum { NtsPacketLength = 1280 }; 
uint8_t nts[NtsPacketLength] = {0};

enum { uniqueIdentifierLength = 32 };

/* TODO: FIXME: rather use a list, in order to support multiple outstanding requests? */
uint8_t uniqueIdentifier [uniqueIdentifierLength] = {0};

enum {
    SymmetricActive = 1,
    SymmetricPassive = 2,
    Client = 3,
    Server = 4,
    BroadcastServer = 5,
    BroadcastClient = 6,
} NtpProtocolModes;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    uint32_t seconds;
    uint32_t fraction;
} timestamp;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    struct __attribute__((packed, scalar_storage_order("big-endian"))) {
        uint8_t leapIndicator:2;
        uint8_t versionNumber:3;
        uint8_t mode:3;
        uint8_t stratum;
        uint8_t poll;
        uint8_t precision;
    };

    uint32_t rootDelay;
    uint32_t rootDispersion;
    uint32_t referenceID;
    timestamp referenceTimestamp;
    timestamp originTimestamp;
    timestamp receiveTimestamp;
    timestamp transmitTimestamp;
} MinimalNtpPacket;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    uint16_t FieldType;
    uint16_t Length;
} ExtensionFieldHeader;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    uint16_t NonceLength;
    uint16_t CiphertextLength;
} AuthenticatorAndEncryptedExtensionHeader;

typedef union __attribute__((packed)) {
    uint8_t fields;
    struct __attribute__((packed)) {
        uint8_t uniqueIdentifier:1;
        uint8_t NtsAuthenticatorAndEncryptedExtensionField:1;
    };
} RequiredNtsExtensionFields;

static ntserror prepareRequest(size_t * ntsLengthOut)
{
    ntserror err = NTS_SUCCESS;
    int ret = 0;
    memset(nts, 0, sizeof(nts));
    uint8_t * nextNtsEntry = nts;
    size_t padLen = 0, cookielength = 0;
    ExtensionFieldHeader * efh;

    /* 48-octet NTP header, implementing draft-ietf-ntp-data-minimization-04 */
    MinimalNtpPacket * ntp = (MinimalNtpPacket*) nextNtsEntry;

    ntp->leapIndicator = 0;
    ntp->versionNumber = 4;
    ntp->mode = Client;
    getRandom((uint8_t*)&(ntp->transmitTimestamp), sizeof(ntp->transmitTimestamp));
    ntp->precision = 0x20;

    Log(NTS_LOG_VERBOSE, LOGPREFIX "Sending NTP header" LOGPOSTFIX);
    Log_Hex( NTS_LOG_TRACE, ntp, sizeof(MinimalNtpPacket) );
    nextNtsEntry += sizeof(MinimalNtpPacket);

    /* authenticated but not encrypted extension fields */

    /* UniqueIdentifier: 32 bytes long CSRNG output */
    efh = (ExtensionFieldHeader *) nextNtsEntry;
    nextNtsEntry += sizeof(ExtensionFieldHeader);

    efh->FieldType = UniqueIdentifierExtensionField;
    /* TODO: FIXME: push uniqueIdentifier into a list, in order to support multiple outstanding requests? */
    getRandom(uniqueIdentifier, sizeof(uniqueIdentifier));
    memcpy(nextNtsEntry, uniqueIdentifier, sizeof(uniqueIdentifier));

    padLen = (4 - uniqueIdentifierLength % 4) % 4;
    efh->Length = (uint16_t)(sizeof(ExtensionFieldHeader) + uniqueIdentifierLength + padLen);

    Log(NTS_LOG_VERBOSE, LOGPREFIX "Sending extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);
    Log_Hex( NTS_LOG_TRACE, efh, efh->Length );
    nextNtsEntry += uniqueIdentifierLength + padLen;

    /* Cookie */
    efh = (ExtensionFieldHeader *) nextNtsEntry;
    nextNtsEntry += sizeof(ExtensionFieldHeader);

    efh->FieldType = NtsCookieExtensionField;
    int remainingBufferLen = (int)sizeof(nts) // total size of buffer
        - (nextNtsEntry - nts) // already used part of buffer
        - (int)sizeof(ExtensionFieldHeader) - (int)sizeof(AuthenticatorAndEncryptedExtensionHeader) - NonceLength - AES_BLOCK_SIZE; // minimum size of final block
    Log( NTS_LOG_TRACE, LOGPREFIX "remainingBufferLen %d" LOGPOSTFIX, remainingBufferLen );
    if (remainingBufferLen < 0 || remainingBufferLen > UINT16_MAX)
    {
        return NTS_BUG_BAD_REMAININGBUFFERLEN;
    }

    if((err = popl_cookie( nextNtsEntry, (uint16_t)remainingBufferLen, &cookielength )) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - no cookie available (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_CANT_POPL_COOKIE;
    }

    padLen = (4 - cookielength % 4) % 4;
    if (sizeof(ExtensionFieldHeader) + cookielength + (size_t)padLen > UINT16_MAX)
    {
        return NTS_BUG_BAD_EFHLENGTH;
    }
    efh->Length = (uint16_t)(sizeof(ExtensionFieldHeader) + cookielength + (size_t)padLen);

    Log(NTS_LOG_VERBOSE, LOGPREFIX "Sending extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);
    Log_Hex( NTS_LOG_TRACE, efh, efh->Length );
    nextNtsEntry += cookielength + padLen;

    /* Ask for missing Cookies */
    int missingCookies = 7 - count_cookies();
    Log( NTS_LOG_TRACE, LOGPREFIX "missing cookies in store: %d" LOGPOSTFIX, missingCookies );
    for (int i = 0; i < missingCookies; ++i)
    {
        efh = (ExtensionFieldHeader *) nextNtsEntry;
        nextNtsEntry += sizeof(ExtensionFieldHeader);

        efh->FieldType = NtsCookiePlaceholderExtensionField;
        Log(NTS_LOG_VERBOSE, LOGPREFIX "Sending extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);

        padLen = (4 - cookielength % 4) % 4;
        if (sizeof(ExtensionFieldHeader) + cookielength + padLen > UINT16_MAX)
        {
            return NTS_BUG_BAD_EFHLENGTH;
        }
        efh->Length = (uint16_t)(sizeof(ExtensionFieldHeader) + cookielength + padLen);

        Log_Hex( NTS_LOG_TRACE, efh, sizeof(ExtensionFieldHeader) + cookielength + padLen );
        nextNtsEntry += cookielength + padLen;
    }
    
    /* extension field containing AEAD output */
    efh = (ExtensionFieldHeader *) nextNtsEntry;
    nextNtsEntry += sizeof(ExtensionFieldHeader);

    efh->FieldType = NtsAuthenticatorAndEncryptedExtensionField;

    AuthenticatorAndEncryptedExtensionHeader * aeeh = (AuthenticatorAndEncryptedExtensionHeader *) nextNtsEntry;
    nextNtsEntry += sizeof(AuthenticatorAndEncryptedExtensionHeader);

    aeeh->NonceLength = NonceLength; 
    uint8_t * nonce = (uint8_t*)nextNtsEntry;
    getRandom( nonce, aeeh->NonceLength );
    int noncePadLen = (4 - aeeh->NonceLength%4)%4;
    nextNtsEntry += aeeh->NonceLength + noncePadLen;

    /* associatedData: from start of NTP header until the end of the extension field preceding the NTS Authenticator */
    uint8_t * associatedData = (uint8_t *)nts;
    int associatedDataLen = (uint8_t*)efh - (uint8_t*)nts;
    if (associatedDataLen < 0)
    {
        return NTS_BUG_BAD_MEMORYORDER;
    }

    const uint8_t * plain = (uint8_t*)"";
    uint32_t plainLen = 0;

    uint8_t * siv = (uint8_t*)nextNtsEntry;
    const uint32_t sivLen = AES_BLOCK_SIZE;
    nextNtsEntry += sivLen;

    uint8_t * encrypted = (uint8_t*)nextNtsEntry;
    uint32_t encryptedLen = plainLen; // AES ciphertext has the same length as the plaintext
    nextNtsEntry += encryptedLen;

    if((ret = wc_AesSivEncrypt(getC2S(), getC2SLength(),
            associatedData, (uint32_t)associatedDataLen,
            nonce, aeeh->NonceLength,
            plain, plainLen,
            siv, encrypted)) != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - AES encrypt failed (aes %d)" LOGPOSTFIX, ret);
        return NTS_BUG_CANT_ENCRYPT;
    }

    if (sivLen + encryptedLen > UINT16_MAX)
    {
        return NTS_BUG_BAD_CIPHERTEXTLENGTH;
    }
    aeeh->CiphertextLength = (uint16_t)(sivLen + encryptedLen);
    int cipherPadLen = (4 - aeeh->CiphertextLength%4)%4;
    nextNtsEntry += cipherPadLen;

    int efhLength = (int)sizeof(ExtensionFieldHeader) + (int)sizeof(AuthenticatorAndEncryptedExtensionHeader) + aeeh->NonceLength + noncePadLen + aeeh->CiphertextLength + cipherPadLen;
    if (efhLength < 0 || efhLength > UINT16_MAX)
    {
        return NTS_BUG_BAD_EFHLENGTH;
    }
    efh->Length = (uint16_t)efhLength;

    Log(NTS_LOG_VERBOSE, LOGPREFIX "Sending extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);

    /* Additional Padding */
    // FIXME: TODO: check wether we need additional padding according to RFC8915.
    // we probably shouldn't, as we included a random 128 bits nonce

    int ntsLen = (uint8_t*)nextNtsEntry - (uint8_t*)nts;
    Log( NTS_LOG_VERBOSE, LOGPREFIX "length of NTS packet is %d bytes" LOGPOSTFIX, ntsLen );

    if(ntsLengthOut == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - output buffer length pointer is null" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }
    if (ntsLen < 0)
    {
        return NTS_BUG_TOO_SHORT_LENGTH;
    }
    *ntsLengthOut = (size_t)ntsLen;
    return NTS_SUCCESS;
}

static ntserror parseNtsAaee(const uint8_t * buf, size_t len, const uint8_t * associatedData, size_t associatedDataLen)
{
    ntserror err = NTS_SUCCESS;
    const uint8_t * nextBuf = buf;
    AuthenticatorAndEncryptedExtensionHeader * aeeh = (AuthenticatorAndEncryptedExtensionHeader*) nextBuf;
    nextBuf += sizeof(AuthenticatorAndEncryptedExtensionHeader);

    if(len < (sizeof(AuthenticatorAndEncryptedExtensionHeader) + aeeh->NonceLength + aeeh->CiphertextLength))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot parse AAEE - header length (%u) doesn't match expected length (%u)" LOGPOSTFIX,
                len, (sizeof(AuthenticatorAndEncryptedExtensionHeader) + aeeh->NonceLength + aeeh->CiphertextLength));
        return NTS_FAULT_TOO_SHORT_AAEE;
    }

    const uint8_t * nonce = nextBuf;
    nextBuf += aeeh->NonceLength + (4 - aeeh->NonceLength%4)%4;

    uint8_t siv[AES_BLOCK_SIZE] = {0};
    const unsigned int sivLen = AES_BLOCK_SIZE;

    if(aeeh->CiphertextLength < sivLen)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot parse AAEE - cipher text length (%d) doesn't match expected length (%d)" LOGPOSTFIX,
                aeeh->CiphertextLength, sivLen);
        return NTS_BUG_TOO_SHORT_CIPHERTEXT;
    }

    memcpy(siv, nextBuf, sivLen);
    nextBuf += sivLen + (4 - sivLen%4)%4;

    const uint8_t * ciphertext = nextBuf;
    if (aeeh->CiphertextLength < sivLen)
    {
        return NTS_DEFECT_TOO_SHORT_CIPHERTEXT;
    }
    const size_t ciphertextLen = aeeh->CiphertextLength - sivLen;
    //nextBuf += ciphertextLen + (4 - ciphertextLen%4)%4; // if extension fields after the AAEE would be of interest

    uint8_t * decrypted = NULL;
    if((decrypted = malloc(ciphertextLen)) == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot parse AAEE - decrypt buffer is null" LOGPOSTFIX);
        return NTS_BUG_CANT_MALLOC;
    }

    Log_Hex( NTS_LOG_TRACE, associatedData, associatedDataLen );
    Log_Hex( NTS_LOG_TRACE, nonce, aeeh->NonceLength );
    Log_Hex( NTS_LOG_TRACE, ciphertext, ciphertextLen );

    int ret;
    if((ret = wc_AesSivDecrypt(getS2C(), getS2CLength(),
            associatedData, associatedDataLen,
            nonce, aeeh->NonceLength,
            ciphertext, ciphertextLen,
            siv, decrypted)) != 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - AES decrypt failed (aes %d)" LOGPOSTFIX, ret);
        free(decrypted);
        return NTS_DEFECT_FAILED_AEADDECRYPT;
    }

    Log(NTS_LOG_DEBUG, LOGPREFIX "Cryptographic verification of NTS response succeeded!" LOGPOSTFIX);

    Log_Hex( NTS_LOG_TRACE, decrypted, ciphertextLen );

    unsigned int remaining = ciphertextLen;
    uint8_t * nextNtsEntry = decrypted;
    ExtensionFieldHeader * efh = NULL;

    while(remaining > 0)
    {
        Log(NTS_LOG_TRACE, LOGPREFIX "while(remaining > 0) loop" LOGPOSTFIX);

        if(remaining < sizeof(ExtensionFieldHeader))
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - Extension Field Header remaining size (%d) smaller than expected (%d)" LOGPOSTFIX,
                    remaining, sizeof(ExtensionFieldHeader));
            err = NTS_DEFECT_TOO_SHORT_REMAINING;
            goto release;
        }

        efh = (ExtensionFieldHeader *) nextNtsEntry;
        nextNtsEntry += sizeof(ExtensionFieldHeader);
        if(efh->Length < sizeof(ExtensionFieldHeader))
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - Extension Field Header length (%d) smaller than expected (%d)" LOGPOSTFIX,
                    efh->Length, sizeof(ExtensionFieldHeader));
            err = NTS_DEFECT_TOO_SHORT_LENGTH;
            goto release;
        }

        if(remaining < efh->Length)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - Extension Field Header remaining size (%d) smaller than EFH length (%d)" LOGPOSTFIX,
                    remaining, efh->Length);
            err = NTS_DEFECT_TOO_SHORT_REMAINING;
            goto release;
        }

        remaining -= efh->Length;
        
        if (((efh->FieldType & 0xff) == 4) && ((efh->FieldType)>>8) <= 4 && ((efh->FieldType)>>8) >= 1)
        {
            Log(NTS_LOG_VERBOSE, LOGPREFIX "Received encrypted extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);
        }

        if(efh->FieldType == NtsCookieExtensionField)
        {
            Log(NTS_LOG_TRACE, LOGPREFIX "Processing (formerly) encrypted NTS Cookie Extension Field" LOGPOSTFIX);
            int cookieLen = efh->Length - (int)sizeof(ExtensionFieldHeader);
            if(cookieLen <= 0)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - invalid Cookie Extension Field Header length (%d)" LOGPOSTFIX,
                        cookieLen);
                err = NTS_DEFECT_TOO_SHORT_EXTENSIONFIELD;
                goto release;
            }

            const uint8_t * cookie = nextNtsEntry;
            Log(NTS_LOG_DEBUG, LOGPREFIX "new Cookie received" LOGPOSTFIX);
            Log_Hex( NTS_LOG_TRACE, cookie, (size_t)cookieLen );

            if (cookieLen > UINT16_MAX)
            {
                return NTS_BUG_BAD_COOKIELENGTH;
            }
            if((err = push_cookie(cookie, (uint16_t)cookieLen)) != NTS_SUCCESS)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot prepare request - cannot push cookie (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
                err = NTS_BUG_CANT_PUSH_COOKIE;
                goto release;
            }

            nextNtsEntry += cookieLen;
        }
        else
        {
            Log(NTS_LOG_WARN, LOGPREFIX "Encountered encrypted NTP Extension Field of unknown type: 0x%04x" LOGPOSTFIX, efh->FieldType);
        }
    }

release:
    free(decrypted);
    return err;
}

static ntserror verifyResponse(const uint8_t * ntsPacket, size_t responseLen)
{
    ntserror err = NTS_SUCCESS;
    const uint8_t * nextNtsEntry = ntsPacket;
    unsigned int remaining = responseLen;
    RequiredNtsExtensionFields res = {0};
    const ExtensionFieldHeader * efh;

    if(remaining < sizeof(MinimalNtpPacket))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - remaining size (%d) smaller than expected (%d)" LOGPOSTFIX,
                remaining, sizeof(MinimalNtpPacket));
        return NTS_FAULT_TOO_SHORT_NTP;
    }

    /* 48-octet NTP header, implementing draft-ietf-ntp-data-minimization-04 */
    const MinimalNtpPacket * ntp = (const MinimalNtpPacket*) nextNtsEntry;
    Log_Hex( NTS_LOG_TRACE, ntp, sizeof(MinimalNtpPacket) );
    nextNtsEntry += sizeof(MinimalNtpPacket);
    remaining -= sizeof(MinimalNtpPacket);

    Log( NTS_LOG_DEBUG, LOGPREFIX "leapIndicator %d, versionNumber %d, mode %d, stratum %d, poll %d, precision %d, rootDelay %d, rootDispersion %d, referenceId %d, referenceTimestamp.sec %u, originTimestamp.sec %u, receiveTimestamp.sec %u, transmitTimestamp.sec %u" LOGPOSTFIX, 
        ntp->leapIndicator,
        ntp->versionNumber,
        ntp->mode,
        ntp->stratum,
        ntp->poll,
        ntp->precision,
        ntp->rootDelay,
        ntp->rootDispersion,
        ntp->referenceID,
        ntp->referenceTimestamp.seconds,
        ntp->originTimestamp.seconds,
        ntp->receiveTimestamp.seconds,
        ntp->transmitTimestamp.seconds
            );

    /* TODO: FIXME: re-perform NTS-KE? (currently done only once) */
    if(ntp->mode != Server)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - invalid NTP mode (%d)" LOGPOSTFIX, ntp->mode);
        return NTS_FAULT_NO_SERVERREPLY;
    }

    if(ntp->versionNumber != 4)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - invalid NTP version (%d)" LOGPOSTFIX, ntp->versionNumber);
        return NTS_FAULT_WRONG_VERSIONNUMBER;
    }

    if (ntp->stratum == 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "kiss-o'-death message received. NTS KE must be rerun, before we can continue." LOGPOSTFIX);
        unsetNts();
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - invalid NTP stratum (%d)" LOGPOSTFIX, ntp->stratum);
        return NTS_FAULT_KISSOFDEATH;
    }

    Log(NTS_LOG_DEBUG, LOGPREFIX "Received NTP header" LOGPOSTFIX);

    const AuthenticatorAndEncryptedExtensionHeader * aeeh = NULL;
    while(remaining > 0)
    {
        Log(NTS_LOG_TRACE, LOGPREFIX "while(remaining > 0) loop" LOGPOSTFIX);

        if(remaining < sizeof(ExtensionFieldHeader))
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - EFH remaining size (%d) smaller than expected Header size (%d)" LOGPOSTFIX,
                    remaining, sizeof(ExtensionFieldHeader));
            return NTS_FAULT_TOO_SHORT_EFH;
        }

        efh = (const ExtensionFieldHeader *) nextNtsEntry;
        nextNtsEntry += sizeof(ExtensionFieldHeader);

        if(efh->Length < sizeof(ExtensionFieldHeader))
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - EFH length (%d) smaller than expected (%d)" LOGPOSTFIX,
                    efh->Length, sizeof(ExtensionFieldHeader));
            return NTS_DEFECT_TOO_SHORT_REMAINING;
        }

        if(remaining < efh->Length)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - EFH remaining size (%d) smaller than EFH length (%d)" LOGPOSTFIX,
                    remaining, efh->Length);
            return NTS_DEFECT_TOO_SHORT_REMAINING;
        }

        remaining -= efh->Length;

        if (((efh->FieldType & 0xff) == 4) && ((efh->FieldType)>>8) <= 4 && ((efh->FieldType)>>8) >= 1)
        {
            Log(NTS_LOG_VERBOSE, LOGPREFIX "Received plain extension field of type %s" LOGPOSTFIX, NtsExtensionFieldTypeStrings[((efh->FieldType)>>8) - 1]);
        }

        if(efh->FieldType == UniqueIdentifierExtensionField)
        {
            uint32_t expectedPaddedLen = sizeof(uniqueIdentifier) + (4 - sizeof(uniqueIdentifier)%4)%4;

            if((efh->Length - sizeof(ExtensionFieldHeader)) != expectedPaddedLen)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - UIEF length (%d) doesn't match expected length (%d)" LOGPOSTFIX,
                        (efh->Length - sizeof(ExtensionFieldHeader)), expectedPaddedLen);
                return NTS_DEFECT_UNEXPECTED_LENGTH;
            }

            Log_Hex( NTS_LOG_TRACE, nextNtsEntry, sizeof(uniqueIdentifier) );

            /* message MUST be discarded if the uniqueIdentifier doesn't match. FIXME: TODO: we might wait or retry? */
            if(strncmp((const char*)nextNtsEntry, (const char*)uniqueIdentifier, sizeof(uniqueIdentifier)) != 0)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - invalid Unique Identifier" LOGPOSTFIX);
                return NTS_FAULT_INVALID_UNIQUEIDENTIFIER;
            }

            nextNtsEntry += efh->Length - sizeof(ExtensionFieldHeader);
            res.uniqueIdentifier = 1;
        }
        else if(efh->FieldType == NtsAuthenticatorAndEncryptedExtensionField)
        {
            if(efh->Length < (sizeof(ExtensionFieldHeader) + sizeof(AuthenticatorAndEncryptedExtensionHeader)))
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - AAEE field length (%d) doesn't match expected length (%d)" LOGPOSTFIX,
                        efh->Length, (sizeof(ExtensionFieldHeader) + sizeof(AuthenticatorAndEncryptedExtensionHeader)));
                return NTS_DEFECT_TOO_SHORT_LENGTH;
            }

            Log_Hex( NTS_LOG_TRACE, nextNtsEntry, efh->Length - sizeof(ExtensionFieldHeader) );

            aeeh = (const AuthenticatorAndEncryptedExtensionHeader *)nextNtsEntry;
            /* FIXME: TODO: check rigorously by considering required padding as well! */
            if(efh->Length < (aeeh->NonceLength + aeeh->CiphertextLength + (int)sizeof(ExtensionFieldHeader) + (int)sizeof(AuthenticatorAndEncryptedExtensionHeader)))
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - AAEE header length (%d) doesn't match expected length (%d)" LOGPOSTFIX,
                        efh->Length, (aeeh->NonceLength + aeeh->CiphertextLength + (int)sizeof(ExtensionFieldHeader) + (int)sizeof(AuthenticatorAndEncryptedExtensionHeader)));
                return NTS_DEFECT_TOO_SHORT_LENGTH;
            }

            int associatedDataLen = (const char*)efh - (const char*)ntsPacket;
            if (associatedDataLen < 0)
            {
                return NTS_BUG_BAD_MEMORYORDER;
            }
            if((err = parseNtsAaee(nextNtsEntry, efh->Length - sizeof(ExtensionFieldHeader), ntsPacket, (size_t)associatedDataLen)) != NTS_SUCCESS)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - parsing AAEE has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
                return NTS_FAULT_FAILED_AAEEPARSE;
            }

            nextNtsEntry += efh->Length - sizeof(ExtensionFieldHeader);
            res.NtsAuthenticatorAndEncryptedExtensionField = 1;
        }
        else // unexpected FieldType?
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - encountered unexpected FieldType: 0x%04x" LOGPOSTFIX, efh->FieldType);
            return NTS_BUG_UNEXPECTED_FIELDTYPE;
        }
    }

    if(res.fields != 0x3)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot verify response - missing fields (0x%x instead of 0x3)" LOGPOSTFIX, res.fields);
        return NTS_FAULT_MISSING_FIELDS_NTS;
    }

    return NTS_SUCCESS;
}

ntserror requestTime(time_t *verifiedTime, uint32_t *milliseconds)
{
    ntserror err = NTS_SUCCESS;
    if(isNtskeSet() != 1)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - NTS Key Exchange host is not set" LOGPOSTFIX);
        return NTS_BUG_NO_NTSKE_HOST;
    }

    if (count_cookies() == 0 || isNtsSet() == 0)
    {
        if((err = ntske(getNtskeHost())) != NTS_SUCCESS)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - NTS Key Exchange failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
            return NTS_FAULT_FAILED_NTSKEREQUEST;
        }
    }

    size_t responseLen = 0;
    size_t requestLen = 0;

    if((err = prepareRequest(&requestLen)) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - preparing the request has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_CANT_PREPAREREQUEST;
    }

    Log_Hex( NTS_LOG_TRACE, nts, requestLen );

    if(isNtsSet() != 1)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - NTS port is not set" LOGPOSTFIX);
        return NTS_BUG_NO_NTS_SET;
    }

    responseLen = NtsPacketLength;
    if((err = PerformUdpRequestWithReply(getNtsHost(), getNtsPort(), nts, requestLen, nts, &responseLen)) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - UdpRequestWithReply failed (libnts x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_FAULT_FAILED_UDPREQUEST;
    }

    if((err = verifyResponse(nts, responseLen)) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - response cannot be verified (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_FAULT_CANT_VERIFY;
    }

    MinimalNtpPacket * ntp = (MinimalNtpPacket*) nts;
    time_t unixtime = (time_t)(ntp->transmitTimestamp.seconds - 2208988800L);
    Log(NTS_LOG_INFO, LOGPREFIX "Verified Unixtime: %lld requested from server \"%s\" on port %d as indicated by NTS KE server \"%s\" on port %d" LOGPOSTFIX, (int64_t)unixtime, getNtsHost(), getNtsPort(), getNtskeHost(), getNtskePort());

    if(verifiedTime == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - time is null" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    if(milliseconds == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot request time - milliseconds is null" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    *verifiedTime = unixtime;
    *milliseconds = ntp->transmitTimestamp.fraction / 4294968; // ceil((2**32-1)/1000) = 4294968

    return NTS_SUCCESS;
}

ntserror getTime(char * buf, size_t maxlen)
{
    char * orgbuf = buf;

    time_t verified_unixtime = 0;
    uint32_t milliseconds = 0;
    ntserror err = NTS_SUCCESS;

    if((err = requestTime(&verified_unixtime, &milliseconds)) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot get time - request has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_FAULT_FAILED_NTS;
    }

    struct tm vt = {0};
    struct tm * gmtime_result = NULL;
    gmtime_result = gmtime_r(&verified_unixtime, &vt);
    if (gmtime_result == NULL)
    {
        Log( NTS_LOG_ERROR, LOGPREFIX "cannot transform date and time to broken down version" LOGPOSTFIX );
        return NTS_BUG_CANT_GMTIME;
    }

    int nPrinted = 0;
    nPrinted = snprintf(buf, maxlen, "%04d-%02d-%02dT%02d:%02d:%02d,%03d+0000 S ",
            vt.tm_year + 1900, vt.tm_mon + 1, vt.tm_mday, vt.tm_hour, vt.tm_min, vt.tm_sec, milliseconds);

    if (nPrinted < 0)
    {
        return NTS_BUG_CANT_SNPRINTF;
    }
    if ((size_t)nPrinted >= maxlen)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot get time - string size (%d) too large for buffer size (%u)" LOGPOSTFIX,
                nPrinted, maxlen);
        return NTS_BUG_TOO_SHORT_TIMEBUFFER;
    }

    buf += nPrinted;
    maxlen -= (size_t)nPrinted;

    int nHashes = count_hashes();
    for (int idx = nHashes-1; idx >= 0; --idx)
    {
        size_t nHexdigits = 0;
        if((err = hash_as_hex_to_buffer((size_t)idx, buf, maxlen, &nHexdigits)) != NTS_SUCCESS)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot get time - failed to convert Hash to hex buffer (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
            return NTS_BUG_TOO_SHORT_TIMEBUFFER;
        }

        Log(NTS_LOG_TRACE, LOGPREFIX "printed hash %d length: %d" LOGPOSTFIX, idx, nHexdigits);
        buf += nHexdigits;
        maxlen -= nHexdigits;

        nPrinted = snprintf(buf, maxlen, " ");
        if (nPrinted < 0)
        {
            return NTS_BUG_CANT_SNPRINTF;
        }
        if ((size_t)nPrinted >= maxlen)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot get time - time buffer length (%d) too large for buffer size (%u)" LOGPOSTFIX,
                    nPrinted, maxlen);
            return NTS_BUG_TOO_SHORT_TIMEBUFFER;
        }

        buf += nPrinted;
        maxlen -= (size_t)nPrinted;
    }

    nPrinted = snprintf(buf, maxlen, "%s", getNtskeHost());
    if (nPrinted < 0)
    {
        return NTS_BUG_CANT_SNPRINTF;
    }
    if((size_t)nPrinted >= maxlen)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot get time - time buffer length (%d) too large for buffer size (%u), cannot print NTS KE host" LOGPOSTFIX,
                nPrinted, maxlen);
        return NTS_BUG_TOO_SHORT_TIMEBUFFER;
    }

    Log(NTS_LOG_TRACE, LOGPREFIX "orgbuf: %s" LOGPOSTFIX, orgbuf);
    return NTS_SUCCESS;
}
