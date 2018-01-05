/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __INSTRUM_COMMON_H__
#define __INSTRUM_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RTLD_NEXT
/*#define __GNU_SOURCE*/
#define __USE_GNU
#endif

#include <dlfcn.h>
#include <errno.h>

#define INSTR_FUNCTION(func) do {			\
		instr_##func = dlsym(RTLD_NEXT, #func);	\
		if (dlerror()) {			\
			errno = EACCES;			\
			instr_##func = NULL;	\
		}					\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* __INSTRUM_COMMON_H__ */
