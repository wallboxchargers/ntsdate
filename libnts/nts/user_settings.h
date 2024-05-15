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
#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#include <stdint.h>
#include <stdio.h>

/* FIXME: how to make this independent of the serendipity of different include guards? */
#include <time.h>
#ifdef _TIME_H
  /* linux's /usr/include/time.h defines _TIME_H and declares gmtime_r(...) and time(...)
   * whereas optee's optee_os/out/export-ta_arm32/include/time.h only defines TIME_H */
#else
  /* when compiling an optee TA we have to provide some libc features ourselves */
  #include "required_basics.h"
  /* compatibility with yocto/optee */
  #undef fallthrough
  #define TFM_ARM
#endif /* _TIME_H */

#include <stdlib.h>

#include "nts/io.h"
#define CUSTOM_RAND_GENERATE rand_gen

#define WOLFSSL_TLS13
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define HAVE_ALPN
#define HAVE_KEYING_MATERIAL
#define HAVE_ENCRYPT_THEN_MAC
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_SIV
#define WOLFSSL_CMAC
#define SINGLE_THREADED
#define WOLFSSL_USER_IO
#define WOLFSSL_GETRANDOM
#define WOLFSSL_DH_CONST
#define WOLFSSL_NO_SOCK
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_WOLFSSL_SERVER
#define KEEP_PEER_CERT
#define SESSION_CERTS
#define SMALL_SESSION_CACHE
#define HAVE_GMTIME_R
#define DEBUG_WOLFSSL
#define WOLFSSL_LOG_PRINTF
#define GCM_TABLE_4BIT
#define HAVE_AESGCM
#define HAVE_TLS_EXTENSIONS
#define HAVE_FFDHE_2048
#define HAVE_HKDF
#define NO_OLD_TLS
#define NO_DES3
#define NO_DSA
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define USE_FAST_MATH
#define ECC_USER_CURVES // do not advertise all curves supported by wolfSSL
#define HAVE_ECC256 // enabled and advertised by default anyway
#define TFM_ECC256
#define TFM_ECC384
#define TFM_ECC512
#define TFM_SMALL_SET
#define TFM_HUGE_SET
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define HAVE_ECC
#define HAVE_POLY1305
#define HAVE_CHACHA
#define HAVE_HASHDRBG
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#undef FP_MAX_BITS
#define FP_MAX_BITS 8192 /* Set to largest RSA key size times 2 IE 4096*2 = 8192 */
#define WOLFSSL_ALT_CERT_CHAINS
#define WOLFSSL_USE_ALIGN

#endif /* USER_SETTINGS_H */
