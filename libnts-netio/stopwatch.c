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
#include <time.h>
#include <string.h>
#include "nts-netio/stopwatch.h"

timespec_stopwatch stopwatch[NTS_STOPWATCH_N_STOPWATCHES] = {0};

static const char * stopwatch_idx_as_string(timespec_stopwatch_index idx)
{
    switch(idx)
    {
        NTS_STOPWATCHES(WRITTEN_AS_CASE)
    }
    return "NTS_STOPWATCH_UNKNOWN";
}

static int64_t stopwatch_get_millis(timespec_stopwatch_index idx)
{
    int64_t millis = 0;
    millis = (stopwatch[idx].stop.tv_sec - stopwatch[idx].start.tv_sec)*1000 + (stopwatch[idx].stop.tv_nsec - stopwatch[idx].start.tv_nsec) / 1000000;
    return millis;
}

ntserror stopwatch_restart(timespec_stopwatch_index idx, const char * name)
{
    ntserror err = NTS_SUCCESS;
    if (name == NULL)
    {
        return NTS_BUG_NULL_POINTER;
    }
    int ret = 0;
    if ((ret = clock_gettime(CLOCK_MONOTONIC, &(stopwatch[idx].start))) != 0)
    {
        return NTS_BUG_FAILED_GETTIME;
    }
    stopwatch[idx].stop = stopwatch[idx].start;
    if (idx != NTS_STOPWATCH_FUNCTION && (stopwatch[idx].name == NULL || strcmp(name, stopwatch[idx].name) != 0))
    {
        stopwatch[NTS_STOPWATCH_FUNCTION].name = name;
        stopwatch[NTS_STOPWATCH_FUNCTION].running = true;
        stopwatch[NTS_STOPWATCH_FUNCTION].start = stopwatch[NTS_STOPWATCH_FUNCTION].stop = stopwatch[idx].start;
    }
    stopwatch[idx].name = name;
    stopwatch[idx].running = true;
    return err;
}

static ntserror stopwatch_read(timespec_stopwatch_index idx)
{
    ntserror err = NTS_SUCCESS;
    int ret = 0;
    if (stopwatch[idx].running == false)
    {
        return NTS_BUG_STOPPED_STOPWATCH;
    }
    if ((ret = clock_gettime(CLOCK_MONOTONIC, &(stopwatch[idx].stop))) != 0)
    {
        return NTS_BUG_FAILED_GETTIME;
    }
    return err;
}

ntserror stopwatch_finish(timespec_stopwatch_index idx)
{
    ntserror err = stopwatch_read(idx);
    stopwatch[idx].running = false;
    return err;
}

ntserror stopwatch_check_millis(timespec_stopwatch_index idx, int64_t maxmillis, const char * where)
{
    ntserror err = NTS_SUCCESS;
    if (stopwatch[idx].running == true)
    {
        err = stopwatch_read(idx);
    }

    int64_t millis = stopwatch_get_millis(idx);
    if (millis >= maxmillis)
    {
        Log(NTS_LOG_WARN, LOGPREFIX "on stopwatch %s %s execution took %lld ms until/past %s, acceptable limit is %lld ms" LOGPOSTFIX, stopwatch_idx_as_string(idx), stopwatch[idx].name, millis, where, maxmillis);
#ifdef STOPWATCH_TIMEOUT_IS_FAULT
        return NTS_FAULT_TOO_LONG_EXECTIME;
#endif
    }
    else
    {
        Log(NTS_LOG_DEBUG, LOGPREFIX "on stopwatch %s %s execution took %lld ms until/past %s, acceptable limit is %lld ms" LOGPOSTFIX, stopwatch_idx_as_string(idx), stopwatch[idx].name, millis, where, maxmillis);
    }

    if (idx != NTS_STOPWATCH_FUNCTION)
    {
        err = stopwatch_check_millis(NTS_STOPWATCH_FUNCTION, STOPWATCH_WARNING_TIMEOUT_MILLISECONDS_FUNCTION, where);
    }

    return err;
}

