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
#ifndef NTSV4_INTERNAL_H
#define NTSV4_INTERNAL_H

__attribute__((warn_unused_result)) static ntserror prepareRequest(size_t * ntsLen);
__attribute__((warn_unused_result)) static ntserror parseNtsAaee(const uint8_t * buf, size_t len, const uint8_t * associatedData, size_t associatedDataLen);
__attribute__((warn_unused_result)) static ntserror verifyResponse(const uint8_t * ntsPacket, size_t responseLen);

#endif /* NTSV4_INTERNAL_H */
