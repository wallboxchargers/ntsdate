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
#include <assert.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <nts_ta.h>
#include <inetsocket_plugin.h>

#include <string.h>
#include <stdint.h>
#include "version.h"
#include "nts/nts.h"
#include "checksum.h"

static uint32_t checksum = 0;

TEE_Result TA_CreateEntryPoint(void)
{
    checksum = calculateTaChecksum();
    Log(NTS_LOG_ERROR, LOGPREFIX "NTS TA started (version " GIT_VERSION " checksum 0x%08x compiled on " __DATE__ " " __TIME__ ")" LOGPOSTFIX, checksum);
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    Log(NTS_LOG_ERROR, LOGPREFIX "NTS TA stopped (version " GIT_VERSION " checksum 0x%08x compiled on " __DATE__ " " __TIME__ ")" LOGPOSTFIX, checksum);
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

    Log(NTS_LOG_INFO, LOGPREFIX "Session to NTS TA opened (version " GIT_VERSION " checksum 0x%08x compiled on " __DATE__ " " __TIME__ ")" LOGPOSTFIX, checksum);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __attribute__((unused)) *sess_ctx)
{
    Log(NTS_LOG_INFO, LOGPREFIX "Session to NTS TA closed (version " GIT_VERSION " checksum 0x%08x compiled on " __DATE__ " " __TIME__ ")" LOGPOSTFIX, checksum);
}

static TEE_Result nts_ta_cmd_setfqdn(char * host, size_t len)
{
    return setNtskeHost(host, len);
}

static TEE_Result nts_ta_cmd_gettime(char * buf, size_t maxlen)
{
    Log( NTS_LOG_VERBOSE, LOGPREFIX "nts_ta_cmd_gettime" LOGPOSTFIX );

    ntserror err = getTime(buf, maxlen);
    if (err != NTS_SUCCESS)
    {
        snprintf(buf, maxlen, "ERROR");
        Log( NTS_LOG_WARN, LOGPREFIX "returning from nts_ta_cmd_gettime with error %s" LOGPOSTFIX, ntsErrorAsString(err) );

        return TEE_ERROR_GENERIC;
    }

    Log( NTS_LOG_VERBOSE, LOGPREFIX "returning from nts_ta_cmd_gettime without error" LOGPOSTFIX);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __attribute__((unused)) *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param __attribute__((unused)) params[4])
{
	uint32_t exp_param_types_instring =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	uint32_t exp_param_types_outstring =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	switch (cmd_id) {
	case NTS_TA_CMD_SETFQDN:
        if (param_types != exp_param_types_instring)
            return TEE_ERROR_BAD_PARAMETERS;
		return nts_ta_cmd_setfqdn((char*) params[0].memref.buffer, params[0].memref.size);
    case NTS_TA_CMD_GETTIME:
        if (param_types != exp_param_types_outstring)
        {
            Log( NTS_LOG_ERROR, LOGPREFIX "NTS_TA_CMD_GETTIME got param_types %u, expected %u" LOGPOSTFIX, param_types, exp_param_types_outstring );
            return TEE_ERROR_BAD_PARAMETERS;
        }
        return nts_ta_cmd_gettime((char*) params[0].memref.buffer, params[0].memref.size);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
