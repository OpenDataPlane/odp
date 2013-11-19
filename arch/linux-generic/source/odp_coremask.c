/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */





#include <odp_coremask.h>


#include <stdlib.h>
#include <stdio.h>
#include <string.h>








void odp_coremask_from_str(const char *str, odp_coremask_t *mask)
{
	uint64_t mask_u64;

	if (strlen(str) > 18) {
		/* more than 64 bits */
		return;
	}

	mask_u64 = strtoull(str, NULL, 16);

	odp_coremask_from_u64(&mask_u64, 1, mask);
}


void odp_coremask_to_str(char *str, int len, const odp_coremask_t *mask)
{
	int ret;

	ret = snprintf(str, len, "0x%"PRIx64"", mask->_u64[0]);

	if (ret >= 0 && ret < len) {
		/* force trailing zero */
		str[len-1] = '\0';
	}
}


void odp_coremask_from_u64(const uint64_t *u64, int num, odp_coremask_t *mask)
{
	int i;

	if (num > ODP_COREMASK_SIZE_U64) {
		/* force max size */
		num = ODP_COREMASK_SIZE_U64;
	}

	for (i = 0; i < num; i++) {
		/* */
		mask->_u64[0] |= u64[i];
	}
}



void odp_coremask_zero(odp_coremask_t *mask)
{
	mask->_u64[0] = 0;
}








