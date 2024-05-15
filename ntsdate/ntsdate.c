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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "io.h"

#include "nts/nts.h"

enum {hostLen = 128};
char ntske_host[hostLen] = {0};
int ntske_valid = 0;
char nts_host[hostLen] = {0};
const int nts_host_maxlen = hostLen;
uint16_t nts_port = 123; // default port is NTP
int nts_valid = 0;

enum {libntsReturnStringLen = 2048};
char libntsReturnString[libntsReturnStringLen] = {0};


int
main(int argc, char **argv)
{
    /* equivalent of set FQDN */
    if (argc > 1)
    {
        fprintf(stderr, "using NTSKE server \"%s\"\n", argv[1]);
        strncpy(ntske_host, argv[1], sizeof(ntske_host)-1);
    }
    else
    {
        const char fallbackhost[] = "ptbtime1.ptb.de";
        fprintf(stderr, "using fallback of \"%s\"\n", fallbackhost);
        strncpy(ntske_host, fallbackhost, sizeof(ntske_host)-1);
    }

    ntserror err = NTS_SUCCESS;
    err = setNtskeHost(ntske_host, strlen(ntske_host));
    if (err != NTS_SUCCESS)
    {
        fprintf(stderr, "setNtskeHost failed with %s\n", ntsErrorAsString(err));
    }

    err = getTime(libntsReturnString, libntsReturnStringLen);
    if (err != NTS_SUCCESS)
    {
        fprintf(stderr, "getTime failed with %s\n", ntsErrorAsString(err));
    }

    printf("%s\n", libntsReturnString);

    return 0;
}
