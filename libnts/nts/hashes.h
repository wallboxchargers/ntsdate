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
#ifndef HASHES_H
#define HASHES_H

void drop_hashes(void);
__attribute__((warn_unused_result)) ntserror store_hash(size_t idx, const uint8_t *der, size_t derLength);
__attribute__((warn_unused_result)) ntserror hash_as_hex_to_buffer(size_t idx, char * buf, size_t maxlen, size_t * outlen);
int count_hashes(void);

#endif /* HASHES_H */
