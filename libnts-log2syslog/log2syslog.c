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
#include <syslog.h>
#include <stddef.h>
#include <stdarg.h>
#include "nts/nts.h"
#include "nts-log2syslog/log2syslog.h"

static ntslog ntslogLevel = NTS_LOG_INFO; // default threshold for messages to be logged

void setNtslogLevel(ntslog level)
{
    ntslogLevel = level;
}

ntslog getNtslogLevel(void)
{
    return ntslogLevel;
}

void
Log(ntslog severity, const char * msg, ...)
{
    if (msg == NULL)
    {
        return;
    }
    if (severity < getNtslogLevel())
    {
        return;
    }
    // map ntslog severity to syslog level
    int syslog_level = LOG_DEBUG;
    switch(severity)
    {
        case NTS_LOG_TRACE:
            syslog_level = LOG_DEBUG;
            break;
        case NTS_LOG_DEBUG:
            syslog_level = LOG_DEBUG;
            break;
        case NTS_LOG_VERBOSE:
            syslog_level = LOG_INFO;
            break;
        case NTS_LOG_INFO:
            syslog_level = LOG_NOTICE;
            break;
        case NTS_LOG_WARN:
            syslog_level = LOG_WARNING;
            break;
        case NTS_LOG_ERROR:
            syslog_level = LOG_ERR;
            break;
        case NTS_LOG_FATAL:
            syslog_level = LOG_CRIT;
            break;
        case NTS_LOG_NONE:
            syslog_level = LOG_DEBUG;
            break;
        default:
            syslog_level = LOG_ALERT;
            break;
    }

    va_list arg;
    va_start(arg, msg);

    vsyslog(syslog_level, msg, arg);

    va_end(arg);
}
