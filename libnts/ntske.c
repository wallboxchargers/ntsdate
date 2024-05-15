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

#include "nts/cookie.h"
#include "nts/remote.h"
#include "nts/nts_lengths.h"
#include "nts/io.h"
#include "nts/io_internal.h"
#include "nts/hashes.h"
#include "nts/ntske.h"
#include "nts/ntske_internal.h"
#include "nts/keys.h"
#include "nts/util.h"

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    uint32_t CriticalBit:1;
    uint32_t RecordType:15;
    uint32_t BodyLength:16;
} NtskeRecordHeader;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    union __attribute__((packed, scalar_storage_order("big-endian"))) {
        struct __attribute__((packed, scalar_storage_order("big-endian"))) {
            uint32_t CriticalBit:1;
            uint32_t RecordType:15;
            uint32_t BodyLength:16;
        };
        uint32_t header_u32;
        NtskeRecordHeader header;
    };
    union __attribute__((packed, scalar_storage_order("big-endian"))) {
        uint8_t  body_u8[ 0xFFFF ]; // maximum size according to RFC8915
        uint16_t body_u16[ 0x7FF ]; // last byte would be inaccessible this way
    };
} NtskeRecord;

typedef union __attribute__((packed)) {
    uint8_t fields;
    struct __attribute__((packed)) {
        uint8_t EndOfMessage:1;
        uint8_t NtsNextProtocolNegotiation:1;
        uint8_t AeadAlgorithmNegotiation:1;
        uint8_t NewCookieForNtp4:1;
    };
} RequiredNtskeResponses;

typedef struct __attribute__((packed, scalar_storage_order("big-endian"))) {
    uint16_t protocolId;
    uint16_t aeadAlgorithm;
    uint8_t direction;
} PerAssociationContext;

typedef enum {
    NtskeEndOfMessage = 0,
    NtskeNtsNextProtocol = 1,
    NtskeError = 2,
    NtskeWarning = 3,
    NtskeAeadAlgorithm = 4,
    NtskeNewCookieForNTPv4 = 5,
    NtskeNTPv4ServerNegotiation = 6,
    NtskeNTPv4PortNegotiation = 7,
    /* "invalid" entry for knowing the number of entries */
    NtskeRecordType_NumEntries = 8,
} NtskeRecordType;

/* This array has to stay in sync with NtskeRecordType! */
const char * const NtskeRecordTypeString[NtskeRecordType_NumEntries] = {
    "NtskeEndOfMessage",
    "NtskeNtsNextProtocol",
    "NtskeError",
    "NtskeWarning",
    "NtskeAeadAlgorithm",
    "NtskeNewCookieForNTPv4",
    "NtskeNTPv4ServerNegotiation",
    "NtskeNTPv4PortNegotiation",
};

typedef enum {
    NtsNextProtocolNTPv4 = 0,
} NtsNextProtocol;

typedef enum {
    AEAD_AES_SIV_CMAC_256 = 15,
} IanaAeadAlgorithm;

static uint8_t myS2C[AeadAesSivCmac256KeyLength] = {0};
static uint8_t myC2S[AeadAesSivCmac256KeyLength] = {0};

enum { AlpnBufLen = 8 };
enum { NTSKE_PORT = 4460 };
const char * const cALPN = "ntske/1";

static ntserror perform_and_process_ntske_request(WOLFSSL * ssl, uint16_t * aeadAlgorithm)
{
    int ret = 0;
    ntserror err = NTS_SUCCESS;
    uint16_t negotiatedAeadAlgorithm = 0xFFFF;
    uint16_t negotiatedNextProtocol = 0xFFFF;
    NtskeRecord rec = {0};
    RequiredNtskeResponses res = {0};
    /* https://www.rfc-editor.org/rfc/rfc8915.html#name-the-nts-key-establishment-p says:
     * Immediately following a successful handshake, the client SHALL send a single request (...)
     * consist[ing] of a sequence of records (...) terminated by a "End of Message" record.
     * */

    Log(NTS_LOG_VERBOSE, LOGPREFIX "Performing NTS Key Exchange request" LOGPOSTFIX);

    /* first record: send the mandatory NTS Next Protocol Negotiation record*/
    rec.CriticalBit = 1; // MUST be set
    rec.RecordType = NtskeNtsNextProtocol;
    rec.BodyLength = 2;
    rec.body_u16[0] = NtsNextProtocolNTPv4;

    Log(NTS_LOG_DEBUG, LOGPREFIX "Sending record of type %s" LOGPOSTFIX, NtskeRecordTypeString[rec.RecordType]);
    Log_Hex( NTS_LOG_TRACE, &rec, rec.BodyLength + sizeof(rec.header) );

    int writeLen = wolfSSL_write(ssl, (char*)&rec, (int)(rec.BodyLength + sizeof(rec.header)));
    if(writeLen < 0 || (unsigned int)writeLen != (rec.BodyLength + sizeof(rec.header)))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot send NTS Next Protocol Negotiation record - bytes written (%d) != body + header size (%u)" LOGPOSTFIX,
                writeLen, rec.BodyLength + sizeof(rec.header));
        return NTS_BUG_FAILED_TOWRITE;
    }

    /* second record: for NTPv4 mandatory AEAD Algorithm Negotiation record */
    rec.CriticalBit = 1; // MAY be set. We only support a single algorithm, so it is critical.
    rec.RecordType = NtskeAeadAlgorithm;
    rec.BodyLength = 2;
    rec.body_u16[0] = AEAD_AES_SIV_CMAC_256;

    Log(NTS_LOG_DEBUG, LOGPREFIX "Sending record of type %s" LOGPOSTFIX, NtskeRecordTypeString[rec.RecordType]);
    Log_Hex( NTS_LOG_TRACE, &rec, rec.BodyLength + sizeof(rec.header) );

    writeLen = wolfSSL_write(ssl, (char*)&rec, (int)(rec.BodyLength + sizeof(rec.header)));
    if(writeLen < 0 || (unsigned int)writeLen != (rec.BodyLength + sizeof(rec.header)))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot send AEAD Algorithm Negotiation record - bytes written (%d) != body + header size (%u)" LOGPOSTFIX,
                writeLen, rec.BodyLength + sizeof(rec.header));
        return NTS_BUG_FAILED_TOWRITE;
    }

    /* third record: mandatory "End of Message" */
    rec.CriticalBit = 1; // MUST be set.
    rec.RecordType = NtskeEndOfMessage;
    rec.BodyLength = 0;

    Log(NTS_LOG_DEBUG, LOGPREFIX "Sending record of type %s" LOGPOSTFIX, NtskeRecordTypeString[rec.RecordType]);
    Log_Hex( NTS_LOG_TRACE, &rec, rec.BodyLength + sizeof(rec.header) );

    writeLen = wolfSSL_write(ssl, (char*)&rec, (int)(rec.BodyLength + sizeof(rec.header)));
    if(writeLen < 0 || (unsigned int)writeLen != (rec.BodyLength + sizeof(rec.header)))
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot send End of Message record - bytes written (%d) != body + header size (%u)" LOGPOSTFIX,
                writeLen, rec.BodyLength + sizeof(rec.header));
        return NTS_BUG_FAILED_TOWRITE;
    }

    do {
        /* read header of next record */
        if((ret = wolfSSL_read(ssl, (char*)&rec.header, sizeof(rec.header))) != sizeof(rec.header))
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot read header of next record - bytes read (%d) != header size (%u)" LOGPOSTFIX,
                    ret, sizeof(rec.header));
            return NTS_FAULT_TOO_SHORT_READ_NTSKE_HEADER;
        }

        /* if indicated read body of next record */
        if (rec.BodyLength > 0)
        {
            if((ret = wolfSSL_read(ssl, (char*)rec.body_u8, rec.BodyLength)) != (rec.BodyLength))
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot read body of next record - bytes read (%d) != header size (%u)" LOGPOSTFIX,
                        ret, sizeof(rec.header));
                return NTS_FAULT_TOO_SHORT_READ_NTSKE_BODY;
            }
        }

        Log_Hex( NTS_LOG_TRACE, &rec, rec.BodyLength + sizeof(rec.header) );

        if(rec.RecordType >= NtskeRecordType_NumEntries)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "unexpected record type (%d)" LOGPOSTFIX, rec.RecordType);
            return NTS_BUG_UNEXPECTED_RECORDTYPE;
        }

        Log(NTS_LOG_DEBUG, LOGPREFIX "Received record of type %s" LOGPOSTFIX, NtskeRecordTypeString[rec.RecordType]);

        /* Process record */
        /* TODO: check rigorously (e.g. that a mandatory Critical Bit is set, etc) */
        if (rec.RecordType == NtskeEndOfMessage) { res.EndOfMessage = 1; break; /* We are done */ }
        else if (rec.RecordType == NtskeNtsNextProtocol) {
            /* IDs listed in response MUST comprise a subset of those listed in the request */
            /* we list exactly one, so either the answer is empty or what we listed */
            /* we require an response and can only continue, if the answer is not empty */
            if((rec.BodyLength / 2) == 0)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "invalid Next Protocol body length (%d)" LOGPOSTFIX, (rec.BodyLength / 2));
                return NTS_BUG_BAD_BODYLENGTH;
            }

            negotiatedNextProtocol = rec.body_u16[0];
            if(negotiatedNextProtocol != NtsNextProtocolNTPv4)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "negotiated Next Protocol (%d) is not NTSv4" LOGPOSTFIX, negotiatedNextProtocol);
                return NTS_BUG_UNEXPECTED_NEXTPROTOCOL;
            }

            res.NtsNextProtocolNegotiation = 1;
        }
        else if (rec.RecordType == NtskeError) {
            /* TODO: We could retry, but only after a minimal interval */
            /* for the meantime: just bail out */
            Log(NTS_LOG_ERROR, LOGPREFIX "received Error record" LOGPOSTFIX);
            return NTS_FAULT_NTSKEERROR;
        }
        else if (rec.RecordType == NtskeWarning) {
            /* TODO: We do not know any warning codes, thus we must treat this as error */
            /* for the meantime: just bail out */
            Log(NTS_LOG_ERROR, LOGPREFIX "received Warning record" LOGPOSTFIX);
            return NTS_FAULT_NTSKEWARNING;
        }
        else if (rec.RecordType == NtskeAeadAlgorithm) {
            if((rec.BodyLength / 2) == 0)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "invalid AEAD algorithm  body length (%d)" LOGPOSTFIX, (rec.BodyLength / 2));
                return NTS_BUG_BAD_BODYLENGTH;
            }

            if(rec.body_u16[0] != AEAD_AES_SIV_CMAC_256)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "unexpected AEAD algorithm  (%d)" LOGPOSTFIX, rec.body_u16[0]);
                return NTS_BUG_UNEXPECTED_AEAD;
            }

            negotiatedAeadAlgorithm = rec.body_u16[0];
            res.AeadAlgorithmNegotiation = 1;
        }
        else if (rec.RecordType == NtskeNewCookieForNTPv4)
        {
            Log(NTS_LOG_DEBUG, LOGPREFIX "new Cookie received" LOGPOSTFIX);
            Log_Hex( NTS_LOG_TRACE, rec.body_u8, rec.BodyLength );

            if((err = push_cookie(rec.body_u8, rec.BodyLength)) != NTS_SUCCESS)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot push new cookie (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
                return NTS_BUG_CANT_PUSH_COOKIE;
            }

            res.NewCookieForNtp4 = 1;
        }
        else if (rec.RecordType == NtskeNTPv4ServerNegotiation) {
            Log(NTS_LOG_DEBUG, LOGPREFIX "NtskeNTPv4ServerNegotiation" LOGPOSTFIX);
            Log_Hex( NTS_LOG_TRACE, rec.body_u8, rec.BodyLength );

            if((err = setNtsHost((char *)rec.body_u8, rec.BodyLength)) != NTS_SUCCESS)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "cannot set NTS host (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
                return NTS_BUG_CANT_SET_NTSHOST;
            }

            Log(NTS_LOG_VERBOSE, LOGPREFIX "nts_host: %s" LOGPOSTFIX, getNtsHost());
        }
        else if (rec.RecordType == NtskeNTPv4PortNegotiation) {
            Log(NTS_LOG_DEBUG, LOGPREFIX "NtskeNTPv4PortNegotiation" LOGPOSTFIX);
            Log_Hex( NTS_LOG_TRACE, rec.body_u8, rec.BodyLength );
            if(rec.BodyLength != sizeof(uint16_t))
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "invalid Port Negotiation body length (%d) != (%d)" LOGPOSTFIX,
                        rec.BodyLength, sizeof(uint16_t));
                return NTS_BUG_BAD_PORTLENGTH;
            }

            setNtsPort(rec.body_u16[0]);
            Log(NTS_LOG_DEBUG, LOGPREFIX "nts_port: %d" LOGPOSTFIX, getNtsPort());
            if(getNtsPort() == 0)
            {
                Log(NTS_LOG_ERROR, LOGPREFIX "invalid NTS port (%d)" LOGPOSTFIX, getNtsPort());
                return NTS_FAULT_INVALID_PORTNUMBER;
            }
        }
        else
        {
            if (rec.CriticalBit == 0)
            {
                Log(NTS_LOG_DEBUG, LOGPREFIX "Received record of unexpected type: 0x%08x" LOGPOSTFIX, rec.header_u32);
            }
            else
            {
                /* RFC8915: "MUST treat it as an error if the Critical Bit is 1" */
                Log(NTS_LOG_ERROR, LOGPREFIX "Received critical record of unexpected type: 0x%08x" LOGPOSTFIX, rec.header_u32);
                return NTS_FAULT_UNEXPECTEDCRITICAL;
            }
        }
    } while (1);

    // check that all four mandatory records were received.
    if(res.fields != 0xF)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "received invalid fields value (0x%08x)" LOGPOSTFIX, res.fields);
        return NTS_FAULT_MISSING_FIELDS_NTSKE;
    }

    if(aeadAlgorithm == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "AEAD algorithm is not set" LOGPOSTFIX);
        return NTS_BUG_NULL_POINTER;
    }

    *aeadAlgorithm = negotiatedAeadAlgorithm;

    return NTS_SUCCESS;
}

enum {
    perAssociationContextLength = 5,
};

static ntserror extract_keys(WOLFSSL * ssl, uint16_t negotiatedAeadAlgorithm)
{
    int ret = WOLFSSL_SUCCESS;
    const char * disambiguatingLabel = "EXPORTER-network-time-security";
    PerAssociationContext perAssociationContext;
    perAssociationContext.protocolId = NtsNextProtocolNTPv4;
    perAssociationContext.aeadAlgorithm = negotiatedAeadAlgorithm;

    /* C2S */
    perAssociationContext.direction = 0;
    Log_Hex( NTS_LOG_TRACE, &perAssociationContext, sizeof(perAssociationContext));

    if((ret = wolfSSL_export_keying_material(ssl, myC2S, AeadAesSivCmac256KeyLength, disambiguatingLabel, strlen(disambiguatingLabel), (const uint8_t*)&perAssociationContext, sizeof(perAssociationContext), 1)) != WOLFSSL_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot extract Association Context C2S (ssl 0x%08x)" LOGPOSTFIX, ret);
        return NTS_BUG_CANT_EXPORT_C2S;
    }
    Log_Hex( NTS_LOG_TRACE, myC2S, AeadAesSivCmac256KeyLength);
    setC2S(myC2S, AeadAesSivCmac256KeyLength);

    /* S2C */
    perAssociationContext.direction = 1;
    Log_Hex( NTS_LOG_TRACE, &perAssociationContext, sizeof(perAssociationContext));

    if((ret = wolfSSL_export_keying_material(ssl, myS2C, AeadAesSivCmac256KeyLength, disambiguatingLabel, strlen(disambiguatingLabel), (uint8_t*)&perAssociationContext, sizeof(perAssociationContext), 1)) != WOLFSSL_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot extract Association Context S2C (ssl 0x%08x)" LOGPOSTFIX, ret);
        return NTS_BUG_CANT_EXPORT_S2C;
    }
    Log_Hex( NTS_LOG_TRACE, myS2C, AeadAesSivCmac256KeyLength);
    setS2C(myS2C, AeadAesSivCmac256KeyLength);

    wolfSSL_FreeArrays(ssl);
    return NTS_SUCCESS;
}

static ntserror store_hashes(WOLFSSL * ssl)
{
    int nCerts = 0;
    ntserror err = NTS_SUCCESS;
    WOLFSSL_X509_CHAIN * chain = NULL;
    if((chain = wolfSSL_get_peer_chain(ssl)) == NULL)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hashes - empty peer chain" LOGPOSTFIX);
        return NTS_BUG_NO_PEERCHAIN;
    }

    if((nCerts = wolfSSL_get_chain_count(chain)) <= 0)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hashes - invalid peer chain count (%d)" LOGPOSTFIX, nCerts);
        return NTS_BUG_EMPTY_PEERCHAIN;
    }

    drop_hashes();
    for (uint16_t idx = 0; idx < nCerts; ++idx)
    {
        Log( NTS_LOG_TRACE, LOGPREFIX "processing certificate with index %d" LOGPOSTFIX, idx );
        unsigned char *der = NULL;
        if((der = wolfSSL_get_chain_cert(chain, idx)) == NULL)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot store hashes - missing DER certificate" LOGPOSTFIX);
            return NTS_BUG_MISSING_CERTIFICATE;
        }

        int derLength = wolfSSL_get_chain_length(chain, idx);

        if (derLength < 0)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "received negative DER length %d" LOGPOSTFIX, derLength);
            return NTS_BUG_NEGATIVE_LENGTH_DER;
        }
        else if((err = store_hash(idx, der, (size_t)derLength)) != NTS_SUCCESS)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "cannot store DER (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
            return NTS_BUG_FAILED_STOREHASH;
        }

        WOLFSSL_X509 * x509 = NULL;
        if((x509 = wolfSSL_get_chain_X509(chain, idx)) == NULL)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "missing X509 certificate" LOGPOSTFIX);
            return NTS_BUG_MISSING_CERTIFICATE;
        }

        const byte* notAfter = NULL;
        const byte* notBefore = NULL;
        const char* CN = NULL;
        if((notAfter = wolfSSL_X509_notAfter(x509)) == NULL)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "missing notAfter date" LOGPOSTFIX);
            wolfSSL_X509_free(x509);
            return NTS_DEFECT_MISSING_DATE;
        }

        if((notBefore = wolfSSL_X509_notBefore(x509)) == NULL)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "missing notBefore date" LOGPOSTFIX);
            wolfSSL_X509_free(x509);
            return NTS_DEFECT_MISSING_DATE;
        }

        if ((CN = wolfSSL_X509_get_subjectCN(x509)) == NULL)
        {
            Log(NTS_LOG_ERROR, LOGPREFIX "missing CN" LOGPOSTFIX);
            wolfSSL_X509_free(x509);
            return NTS_DEFECT_MISSING_CN;
        }

        Log(NTS_LOG_VERBOSE, LOGPREFIX "Certificate: CN: %s, notBefore: %s, notAfter: %s" LOGPOSTFIX, CN, notBefore+2, notAfter+2);

        wolfSSL_X509_free(x509);
    }

    return NTS_SUCCESS;
}

ntserror
ntske(const char * domain)
{
    ntserror err = NTS_SUCCESS;
    err = drop_cookies();
    if (err != NTS_SUCCESS)
    {
        return err;
    }
    uint16_t negotiatedAeadAlgorithm = 0xFFFF;
    char ALPN[AlpnBufLen] = {0};
    strncpy(ALPN, cALPN, sizeof(ALPN));

    WOLFSSL_CTX * ctx = NULL;
    WOLFSSL * ssl = NULL;

    int ret;
    if((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - SSL init has failed" LOGPOSTFIX);
        return NTS_BUG_CANT_INIT_WOLFSSL;
    }

    if((ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method())) == NULL)
    {
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - context is missing" LOGPOSTFIX);
        return NTS_BUG_FAILED_TLS13CLIENT;
    }

#ifdef NTSKE_VERIFY_CHAIN
    extern const unsigned char ROOT_CAs_buffer[];
    extern const int ROOT_CAs_buffer_len;

    ret = wolfSSL_CTX_load_verify_buffer(ctx, ROOT_CAs_buffer, ROOT_CAs_buffer_len, SSL_FILETYPE_PEM);
    if(ret != WOLFSSL_SUCCESS)
    {
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - load verify buffer has failed (0x%08x)" LOGPOSTFIX, ret);
        return NTS_BUG_FAILED_LOAD_VERIFYBUFFER;
    }
#else
    Log(NTS_LOG_INFO, LOGPREFIX "NTS Key Exchange - not loading any verify buffer" LOGPOSTFIX);
#endif

    if((err = SetupTcp(domain, NTSKE_PORT)) != NTS_SUCCESS)
    {
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - setup TCP has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_FAILED_SETUPTCP;
    }

    Log(NTS_LOG_TRACE, LOGPREFIX "SetupTcp done" LOGPOSTFIX);

    /* tell CTX about IO */
    wolfSSL_SetIORecv(ctx, TcpRecvWolfCallback);
    wolfSSL_SetIOSend(ctx, TcpSendWolfCallback);

    /* new SSL session */
    if((ssl = wolfSSL_new(ctx)) == NULL)
    {
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - SSL struct is null" LOGPOSTFIX);
        return NTS_BUG_FAILED_WOLFSSL_NEW;
    }

#ifdef NTSKE_VERIFY_CHAIN
    /* Enforce verification of server certificate. Ensure dn matches our expectation */
    wolfSSL_set_verify(ssl, (WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT), NULL);
#else
    /* Explicitly skip verification of certificate chain presented by the server */
    wolfSSL_set_verify(ssl, (WOLFSSL_VERIFY_NONE), NULL);
#endif
    if((ret = wolfSSL_check_domain_name(ssl, domain)) != WOLFSSL_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - check domain name has failed (ssl 0x%08x)" LOGPOSTFIX, ret);
        return NTS_BUG_CANT_CHECKDOMAIN;
    }

    if((ret = wolfSSL_UseALPN(ssl, ALPN, strlen(ALPN), WOLFSSL_ALPN_MATCH | WOLFSSL_ALPN_FAILED_ON_MISMATCH)) != WOLFSSL_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - use ALPN has failed (ssl 0x%08x)" LOGPOSTFIX, ret);
        return NTS_BUG_CANT_USEALPN;
    }

    /* Connect using blocking IO. */
    wolfSSL_KeepArrays(ssl);
    if((ret = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - SSL connect has failed (ssl 0x%08x)" LOGPOSTFIX, ret);
        return NTS_FAULT_FAILED_TLSHANDSHAKE;
    }

    if((err = store_hashes(ssl)) != NTS_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - storing hashes has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_FAILED_STOREHASHES;
    }

    /* nts_host defaults to ntske host and nts_port to NTP. Will be set upon receiving 
     * a NtskeNTPv4ServerNegotiation or NtskeNTPv4PortNegotiation respectively. */
    Log(NTS_LOG_TRACE, LOGPREFIX "nts_host: %s, domain: %s" LOGPOSTFIX, getNtsHost(), domain);
    unsetNts();

    if((err = perform_and_process_ntske_request(ssl, &negotiatedAeadAlgorithm)) != NTS_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - performing NTS KE request has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_FAULT_FAILED_NTSKEREQUEST;
    }

    Log(NTS_LOG_TRACE, LOGPREFIX "after perform_and_process_ntske_request" LOGPOSTFIX);
    if((err = extract_keys(ssl, negotiatedAeadAlgorithm)) != NTS_SUCCESS)
    {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();

        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - extracting keys has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_FAILED_KEYEXTRACTION;
    }

    Log(NTS_LOG_TRACE, LOGPREFIX "after extract_keys" LOGPOSTFIX);

    if (strlen(getNtsHost()) == 0)
    {
        Log(NTS_LOG_VERBOSE, LOGPREFIX "setting NtsHost to domain" LOGPOSTFIX);
        setNtsHost(domain, strlen(domain));
    }
    if (getNtsPort() == 0)
    {
        Log(NTS_LOG_VERBOSE, LOGPREFIX "setting NtsPort to default" LOGPOSTFIX);
        setNtsPort(123); // default is NTP
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    if((err = TeardownTcp()) != NTS_SUCCESS)
    {
        Log(NTS_LOG_ERROR, LOGPREFIX "NTS Key Exchange - teardown TCP has failed (libnts 0x%08x, %s)" LOGPOSTFIX, err, ntsErrorAsString(err));
        return NTS_BUG_FAILED_TEARDOWNTCP;
    }

    return NTS_SUCCESS;
}
