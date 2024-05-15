/* ntsdate - perform a NTS-KE and query once an NTP server supporting NTS using libnts
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#ifndef NTS_TA_H
#define NTS_TA_H

#define NTS_TA_UUID { 0x9a743b32, 0x06a5, 0x4e32, {0xbf, 0x15, 0x82, 0xde, 0x3d, 0xc4, 0x94, 0x72} }

/* trigger to use a plugin */
#define NTS_TA_CMD_SETFQDN   0
#define NTS_TA_CMD_GETTIME   1

#endif /* NTS_TA_H */
