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
#ifndef REMOTE_H
#define REMOTE_H

#include "nts/nts_error.h"
#include <stdint.h>

ntserror setNtskeHost(const char * fqdn, size_t maxlen);
ntserror setNtsHost(const char * host, size_t maxlen);
const char * getNtskeHost(void);
const char * getNtsHost(void);
uint16_t getNtskePort(void);
uint16_t getNtsPort(void);
void setNtsPort(uint16_t port);
void unsetNts(void);
int isNtsSet(void);
int isNtskeSet(void);

#endif /* REMOTE_H */
