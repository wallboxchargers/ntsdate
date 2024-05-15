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
#ifndef COOKIE_H
#define COOKIE_H

#include "nts/nts_error.h"

__attribute__((warn_unused_result)) ntserror push_cookie(const uint8_t * buf, uint16_t len);
__attribute__((warn_unused_result)) ntserror popl_cookie(uint8_t * buf, uint16_t maxlen, size_t * lenOut);
int count_cookies(void);
__attribute__((warn_unused_result)) ntserror drop_cookies(void);

#endif /* COOKIE_H */
