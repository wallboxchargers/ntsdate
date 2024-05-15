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
#include "io.h"

#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "nts/nts.h"

ntslog getNtslogLevel(void)
{
    return NTS_LOG_TRACE;
}

void
Log(ntslog severity, const char * msg, ...)
{
    if(msg != NULL)
    {
        va_list arg;
        va_start(arg, msg);

        fprintf(stderr, "%s", ntsLoglevelAsString(severity));
        fprintf(stderr, ": ");
        vfprintf(stderr, msg, arg);
        fprintf(stderr, "\n");

        va_end(arg);
    }
}

int
getRandom(uint8_t * buf, size_t len)
{
    int readBytes = 0;
    readBytes = getrandom(buf, len, 0);
    if (readBytes < 0 || (size_t)readBytes != len)
    {
        fprintf(stderr, "getrandom returned %d, but %zu bytes were requested!\n", readBytes, len);
        exit(-__LINE__);
    }
    return readBytes;
}

uint32_t
rand_gen(void)
{
    uint32_t rnd;
    int readBytes = 0;
    size_t len = sizeof(rnd);
    readBytes = getrandom((char*)&rnd, len, 0);
    if (readBytes < (int)len)
    {
        fprintf(stderr, "FATAL: getrandom is starving!\n");
        exit(-__LINE__);
    }
    return rnd;
}

/* Allow using libnts compiled for an optee TA in a normal-world-only executable
 * by mapping mdbg_malloc and mdbg_realloc (from optee) back to normal libc
 * malloc and realloc calls.
 * */
void *mdbg_malloc(size_t size)
{
    return malloc(size);
}

void *mdbg_realloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}
