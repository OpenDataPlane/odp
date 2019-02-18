/* Copyright (c) 2019, Nokia
 * Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SHM_INTERNAL_H_
#define ODP_SHM_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <inttypes.h>

#include <odp/api/shared_memory.h>

/* flags available at ishm_reserve: */
#define _ODP_ISHM_SINGLE_VA		1
#define _ODP_ISHM_LOCK			2
#define _ODP_ISHM_EXPORT		4 /* create export descr file in /tmp */

/**
 * Shared memory block info
 */
typedef struct _odp_ishm_info_t {
	const char *name;      /**< Block name */
	void       *addr;      /**< Block address */
	uint64_t    size;      /**< Block size in bytes */
	uint64_t    page_size; /**< Memory page size */
	uint32_t    flags;     /**< _ODP_ISHM_* flags */
	uint32_t    user_flags;/**< user specific flags */
} _odp_ishm_info_t;

int   _odp_ishm_reserve(const char *name, uint64_t size, int fd, uint32_t align,
			uint64_t offset, uint32_t flags, uint32_t user_flags);
int   _odp_ishm_free_by_index(int block_index);
int   _odp_ishm_lookup_by_name(const char *name);
int   _odp_ishm_find_exported(const char *remote_name,
			      pid_t external_odp_pid,
			      const char *local_name);
void *_odp_ishm_address(int block_index);
int   _odp_ishm_info(int block_index, _odp_ishm_info_t *info);
int   _odp_ishm_status(const char *title);
int _odp_ishm_cleanup_files(const char *dirpath);
void _odp_ishm_print(int block_index);

#ifdef __cplusplus
}
#endif

#endif
