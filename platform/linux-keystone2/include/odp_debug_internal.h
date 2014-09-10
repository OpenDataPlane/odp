/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_DEBUG_INTERNAL_H_
#define ODP_DEBUG_INTERNAL_H_

#include <stdio.h>
#include <odp_debug.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ODP_PRINT_LEVEL_DISABLED 0
#define ODP_PRINT_LEVEL_CRIT     1
#define ODP_PRINT_LEVEL_ERR      2
#define ODP_PRINT_LEVEL_WARN     3
#define ODP_PRINT_LEVEL_INFO     4
#define ODP_PRINT_LEVEL_DBG      5
#define ODP_PRINT_LEVEL_VDBG     6
#define ODP_PRINT_LEVEL_MAX      7

#define ODP_PRINT_LEVEL ODP_PRINT_LEVEL_WARN

/**
 * Internal debug printing macro
 */
#ifndef ODP_NO_PRINT
#define odp_print(level, fmt, ...)                                    \
		do { if (level <= ODP_PRINT_LEVEL)                    \
			fprintf(stderr, "%s():%d: " fmt,              \
				__func__, __LINE__, ##__VA_ARGS__);   \
		} while (0)
#else
#define odp_print(level, fmt, ...)
#endif

#define odp_pr_err(fmt, ...)  \
		odp_print(ODP_PRINT_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define odp_pr_warn(fmt, ...) \
		odp_print(ODP_PRINT_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define odp_pr_info(fmt, ...) \
		odp_print(ODP_PRINT_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define odp_pr_dbg(fmt, ...)  \
		odp_print(ODP_PRINT_LEVEL_DBG, fmt, ##__VA_ARGS__)
#define odp_pr_vdbg(fmt, ...) \
		odp_print(ODP_PRINT_LEVEL_VDBG, fmt, ##__VA_ARGS__)

void odp_print_mem(void *addr, size_t size, const char *desc);

static inline void odp_pr_mem(int level, void *addr, size_t size,
				const char *desc)
{
	if (level <= ODP_PRINT_LEVEL)
		odp_print_mem(addr, size, desc);
}

#define odp_pr_err_mem(...)  odp_pr_mem(ODP_PRINT_LEVEL_ERR, ##__VA_ARGS__)
#define odp_pr_dbg_mem(...)  odp_pr_mem(ODP_PRINT_LEVEL_DBG, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif
