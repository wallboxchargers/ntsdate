/* inetsocket - tee supplicant plugin providing TCP and UDP transport
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#ifndef INETSOCKET_PLUGIN_H
#define INETSOCKET_PLUGIN_H

#include <stdint.h>

#define INETSOCKET_PLUGIN_UUID {0xe0bb2422, 0xa34e, 0x4972, {0x9c, 0x4f, 0x17, 0xad, 0x2e, 0x7e, 0xe9, 0x65} }

enum {
    INETSOCKET_PLUGIN_CMD_SETUPTCP    = 0,
    INETSOCKET_PLUGIN_CMD_SENDTCP     = 1,
    INETSOCKET_PLUGIN_CMD_RECVTCP     = 2,
    INETSOCKET_PLUGIN_CMD_TEARDOWNTCP = 3,
    INETSOCKET_PLUGIN_CMD_SETUPUDP    = 4,
    INETSOCKET_PLUGIN_CMD_SENDUDP     = 5,
    INETSOCKET_PLUGIN_CMD_RECVUDP     = 6,
    INETSOCKET_PLUGIN_CMD_TEARDOWNUDP = 7,
    INETSOCKET_PLUGIN_CMD_GETLINUXTIME= 8,
    INETSOCKET_PLUGIN_CMD_UDPREQUEST  = 9,
};

enum { iobufLen = 1280+2*2 };

typedef struct __attribute__((packed)) {
    uint16_t port;
    uint16_t msgLen;
    char host[iobufLen - 2*sizeof(uint16_t)];
} PortDestMsg;

#endif /* INETSOCKET_PLUGIN_H */
