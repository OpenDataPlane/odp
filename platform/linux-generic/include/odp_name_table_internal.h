/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 EZchip Semiconductor Ltd.
 * Copyright (c) 2015-2018 Linaro Limited
 */

#ifndef ODP_INT_NAME_TABLE_H_
#define ODP_INT_NAME_TABLE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum {
	ODP_COS_HANDLE,
	ODP_PKTIO_HANDLE,
	ODP_POOL_HANDLE,
	ODP_QUEUE_HANDLE,
	ODP_RING_HANDLE,
	ODP_SHM_HANDLE,
	ODP_TIMER_POOL_HANDLE,
	ODP_TM_HANDLE,
	ODP_TM_SHAPER_PROFILE_HANDLE,
	ODP_TM_SCHED_PROFILE_HANDLE,
	ODP_TM_THRESHOLD_PROFILE_HANDLE,
	ODP_TM_WRED_PROFILE_HANDLE,
	ODP_TM_NODE_HANDLE
} _odp_int_name_kind_t;

typedef uint32_t _odp_int_name_t;
#define ODP_INVALID_NAME   0

#define _ODP_INT_NAME_LEN 32

_odp_int_name_t _odp_int_name_tbl_add(const char *name,
				      uint8_t     name_kind,
				      uint64_t    user_data);

_odp_int_name_t _odp_int_name_tbl_lookup(const char *name,
					 uint8_t     name_kind);

int _odp_int_name_tbl_delete(_odp_int_name_t odp_name);

const char *_odp_int_name_tbl_name(_odp_int_name_t odp_name);

uint64_t _odp_int_name_tbl_user_data(_odp_int_name_t odp_name);

void _odp_int_name_tbl_stats_print(void);

int _odp_int_name_tbl_init_global(void);
int _odp_int_name_tbl_term_global(void);

#ifdef __cplusplus
}
#endif

#endif
