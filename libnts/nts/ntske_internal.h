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
#ifndef NTSKE_INTERNAL_H
#define NTSKE_INTERNAL_H

__attribute__((warn_unused_result)) static ntserror perform_and_process_ntske_request(WOLFSSL * ssl, uint16_t * aeadAlgorithm);
__attribute__((warn_unused_result)) static ntserror extract_keys(WOLFSSL * ssl, uint16_t negotiatedAeadAlgorithm);
__attribute__((warn_unused_result)) static ntserror store_hashes(WOLFSSL * ssl);

#endif /* NTSKE_INTERNAL_H */
