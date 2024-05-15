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
#ifndef IO_H
#define IO_H

#include <stdint.h>
#include <stddef.h>
#include "nts/nts_error.h"

__attribute__((warn_unused_result)) ntserror SetupTcp(const char * dest_str, uint16_t port);
__attribute__((warn_unused_result)) ntserror TcpRecvCallback(char *buf, size_t sz, size_t * outLen);
__attribute__((warn_unused_result)) ntserror TcpSendCallback(char *buf, size_t sz, size_t * outLen);
__attribute__((warn_unused_result)) ntserror TeardownTcp(void);

__attribute__((warn_unused_result)) ntserror PerformUdpRequestWithReply(const char * host, uint16_t port, uint8_t *ibuf, size_t len, uint8_t * obuf, size_t * outlen);

void Log(ntslog severity, const char * msg, ...)  __attribute__((format(printf, 2, 3)));
ntslog getNtslogLevel(void);

int getRandom(uint8_t * buf, size_t len);
int getrandom(void * buf, size_t len, unsigned int flags);
uint32_t rand_gen(void);

#endif /* IO_H */
