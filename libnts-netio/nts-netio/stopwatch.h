/* libnts-netio - reference implementation of custom transport interface of libnts
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#ifndef _STOPWATCH_H_
#define _STOPWATCH_H_

#include <time.h>
#include "nts/nts.h"
#include "stdbool.h"

#define NTS_STOPWATCHES(X) \
    X( NTS_STOPWATCH_TCP, ) \
    X( NTS_STOPWATCH_UDP, ) \
    X( NTS_STOPWATCH_FUNCTION, ) \
    X( NTS_STOPWATCH_PLUGIN, ) \
    X( NTS_STOPWATCH_N_STOPWATCHES, ) \

#define STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_FUNCTION 2000
#define STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_TCP 3000
#define STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_UDP 3000

typedef struct {
    struct timespec start;
    struct timespec stop;
    bool running;
    const char * name;
} timespec_stopwatch;

typedef enum {
    NTS_STOPWATCHES(WRITTEN_AS_ENUMENTRY)
} timespec_stopwatch_index;

ntserror stopwatch_restart(timespec_stopwatch_index idx, const char * name);
ntserror stopwatch_finish(timespec_stopwatch_index idx);
ntserror stopwatch_check_millis(timespec_stopwatch_index idx, int64_t maxmillis, const char * where);

#endif /* _STOPWATCH_H_ */
