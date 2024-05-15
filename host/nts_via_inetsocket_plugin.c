/* nts_via_inetsocket_plugin - proof of concept for RFC8915 and custom transport
 * Copyright (C) 2024: ABL GmbH
 *
 * This program is available under two distinct licenses:
 * You may either choose to
 *  a) adhere to the GNU General Public License version 2,
 *     as published by the Free Software Foundation, or
 *  b) obtain a commercial license from ABL GmbH,
 *     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.
 * */
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <nts_ta.h>

#define NUMBER_OF_NTS_REQUESTS 12

int main(void)
{
    char domain[128] = {0};
	int i = 0;
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_UUID uuid = NTS_TA_UUID;
	uint32_t err_origin = 0;
    const int outbufLen = 1024;
    char * outbuf = (char*)malloc(outbufLen);
    if (outbuf == NULL)
    {
        printf("FATAL: can't malloc outbuf\n");
        return -1;
    }

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code %#" PRIx32 " origin %#" PRIx32, res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    strncpy(domain, "sth1.nts.netnod.se", sizeof(domain));
    op.params[0].tmpref.buffer = domain;
    op.params[0].tmpref.size = strlen(domain)+1;

	/*
	 * TA will refer to the inetsocket plugin to establish TCP and UDP connections
	 */

	printf("Procedure: REE --> NTS TA --> inetsocket plugin in REE --> internet\n");

    res = TEEC_InvokeCommand(&sess, NTS_TA_CMD_SETFQDN, &op, &err_origin);

    printf("Attempt #%d: TEEC_InvokeCommand() %s; res=%#" PRIx32 " orig=%#" PRIx32 "\n",
           ++i, (res == TEEC_SUCCESS) ? "success" : "failed", res, err_origin);


    for (int k = 0; k < NUMBER_OF_NTS_REQUESTS; ++k) {
        memset(outbuf, 0, outbufLen);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = outbuf;
        op.params[0].tmpref.size = 1023;

        res = TEEC_InvokeCommand(&sess, NTS_TA_CMD_GETTIME, &op, &err_origin);

        printf("Attempt #%d: TEEC_InvokeCommand() %s; res=%#" PRIx32 " orig=%#" PRIx32 "\n", ++i, (res == TEEC_SUCCESS) ? "success" : "failed", res, err_origin);

        if (res == TEEC_SUCCESS)
        {
            printf("verified timestamp:\n%s\n", outbuf);
        }
        else
        {
            printf("failed to get a reliable timestamp!\n");
        }
    }


	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    strncpy(domain, "ptbtime1.ptb.de", sizeof(domain));
    op.params[0].tmpref.buffer = domain;
    op.params[0].tmpref.size = strlen(domain)+1;

    res = TEEC_InvokeCommand(&sess, NTS_TA_CMD_SETFQDN, &op, &err_origin);

    printf("Attempt #%d: TEEC_InvokeCommand() %s; res=%#" PRIx32 " orig=%#" PRIx32 "\n",
           ++i, (res == TEEC_SUCCESS) ? "success" : "failed", res, err_origin);


    for (int k = 0; k < NUMBER_OF_NTS_REQUESTS; ++k) {
        memset(outbuf, 0, outbufLen);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
        op.params[0].tmpref.buffer = outbuf;
        op.params[0].tmpref.size = 1023;

        res = TEEC_InvokeCommand(&sess, NTS_TA_CMD_GETTIME, &op, &err_origin);

        printf("Attempt #%d: TEEC_InvokeCommand() %s; res=%#" PRIx32 " orig=%#" PRIx32 "\n", ++i, (res == TEEC_SUCCESS) ? "success" : "failed", res, err_origin);

        if (res == TEEC_SUCCESS)
        {
            printf("verified timestamp:\n%s\n", outbuf);
        }
        else
        {
            printf("failed to get a reliable timestamp!\n");
        }
    }


	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
