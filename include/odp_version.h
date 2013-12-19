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


/**
 * @file
 *
 * ODP version
 */

#ifndef ODP_VERSION_H_
#define ODP_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif


/**
 * ODP API main version
 *
 * Introduction of major new features or changes. APIs with different major
 * versions are likely not backward compatible.
 */
#define ODP_VERSION_API_MAIN  0

/**
 * ODP API sub version
 *
 * Introduction of additional features or minor changes. APIs with common
 * major version and different sub versions may be backward compatible (if only
 * additions).
 */
#define ODP_VERSION_API_SUB   0

/**
 * ODP API bug correction version
 *
 * Bug corrections to the API files. APIs with the same major and sub
 * versions, but different bug correction versions are backward compatible.
 */
#define ODP_VERSION_API_BUG   1



#define ODP_VERSION_STR_EXPAND(x)  #x
#define ODP_VERSION_TO_STR(x)      ODP_VERSION_STR_EXPAND(x)

#define ODP_VERSION_API_STR \
ODP_VERSION_TO_STR(ODP_VERSION_API_MAIN) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_SUB) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_BUG)


/**
 * Returns ODP API version string
 */
static inline const char *odp_version_api_str(void)
{
	return ODP_VERSION_API_STR;
}




#ifdef __cplusplus
}
#endif

#endif







