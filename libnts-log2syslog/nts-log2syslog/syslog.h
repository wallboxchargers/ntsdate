/* libnts-log2syslog - example implementation of the Log interface of libnts using vsyslog
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#ifndef _SYSLOG_INTERNAL_H_
#define _SYSLOG_INTERNAL_H_
/* This header is designed exclusively for special setups having to tunnel syslog messages through custom transport */

#include <stdarg.h>

/* Copied from "8.1 (Berkeley) 6/2/93" /usr/include/sys/syslog.h shipped with Debian 11 */
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

/* /usr/include/bits/syslog.h shipped with Debian 11 implents
 * void vsyslog(int priority, const char * format, va_list ap) __attribute__((format (printf, 2, 0)));
 * as wrapper around __vsyslog_chk
 * which is part of the "Interface Definitions for libc" according to the Linux Standard Base Core Specification 5.0.
 * */
void __vsyslog_chk(int priority, int flag, const char * format, va_list ap) __attribute__((format (printf, 3, 0)));

#endif /* _SYSLOG_INTERNAL_H_ */
