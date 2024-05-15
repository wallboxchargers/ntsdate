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
#ifndef IO_INTERNAL_H
#define IO_INTERNAL_H

#include "nts/user_settings.h"
#include <wolfssl/ssl.h>
int TcpRecvWolfCallback(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int TcpSendWolfCallback(WOLFSSL *ssl, char *buf, int sz, void *ctx);

#endif /* IO_INTERNAL_H */
