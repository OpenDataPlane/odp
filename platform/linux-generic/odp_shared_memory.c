/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/debug.h>
#include <odp/api/std_types.h>
#include <odp/api/shared_memory.h>
#include <odp/api/plat/strong_types.h>
#include <odp_shm_internal.h>
#include <odp_init_internal.h>
#include <odp_global_data.h>
#include <string.h>

/* Supported ODP_SHM_* flags */
#define SUPPORTED_SHM_FLAGS (ODP_SHM_PROC | ODP_SHM_SINGLE_VA | ODP_SHM_EXPORT | \
			     ODP_SHM_HP | ODP_SHM_NO_HP)

static inline uint32_t from_handle(odp_shm_t shm)
{
	return _odp_typeval(shm) - 1;
}

static inline odp_shm_t to_handle(uint32_t index)
{
	return _odp_cast_scalar(odp_shm_t, index + 1);
}

static uint32_t get_ishm_flags(uint32_t flags)
{
	uint32_t f = 0; /* internal ishm flags */

	/* set internal ishm flags according to API flags:
	 * note that both ODP_SHM_PROC and ODP_SHM_EXPORT maps to
	 * _ODP_ISHM_LINK as in the linux-gen implementation there is
	 * no difference between exporting to another ODP instance or
	 * another linux process */
	f |= (flags & (ODP_SHM_PROC | ODP_SHM_EXPORT)) ? _ODP_ISHM_EXPORT : 0;
	f |= (flags & ODP_SHM_SINGLE_VA) ? _ODP_ISHM_SINGLE_VA : 0;

	return f;
}

int odp_shm_capability(odp_shm_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_shm_capability_t));

	capa->max_blocks = CONFIG_SHM_BLOCKS;
	capa->max_size = odp_global_ro.shm_max_size;
	capa->max_align = 0;
	capa->flags = SUPPORTED_SHM_FLAGS;

	return 0;
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	int block_index;
	uint32_t flgs = 0; /* internal ishm flags */
	uint32_t supported_flgs = SUPPORTED_SHM_FLAGS;

	if (flags & ~supported_flgs) {
		_ODP_ERR("Unsupported SHM flag\n");
		return ODP_SHM_INVALID;
	}

	flgs = get_ishm_flags(flags);

	block_index = _odp_ishm_reserve(name, size, -1, align, 0, flgs, flags);
	if (block_index >= 0)
		return to_handle(block_index);
	else
		return ODP_SHM_INVALID;
}

odp_shm_t odp_shm_import(const char *remote_name,
			 odp_instance_t odp_inst,
			 const char *local_name)
{
	int ret;

	ret =  _odp_ishm_find_exported(remote_name, (pid_t)odp_inst,
				       local_name);

	return to_handle(ret);
}

int odp_shm_free(odp_shm_t shm)
{
	return _odp_ishm_free_by_index(from_handle(shm));
}

odp_shm_t odp_shm_lookup(const char *name)
{
	return to_handle(_odp_ishm_lookup_by_name(name));
}

void *odp_shm_addr(odp_shm_t shm)
{
	return _odp_ishm_address(from_handle(shm));
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	_odp_ishm_info_t ishm_info;

	if (_odp_ishm_info(from_handle(shm), &ishm_info))
		return -1;

	info->name = ishm_info.name;
	info->addr = ishm_info.addr;
	info->size = ishm_info.size;
	info->page_size = ishm_info.page_size;
	info->flags = ishm_info.user_flags;
	info->num_seg = 1;

	return 0;
}

int odp_shm_segment_info(odp_shm_t shm, uint32_t index, uint32_t num,
			 odp_shm_segment_info_t seg_info[])
{
	odp_shm_info_t info;

	/* No physical memory segment information available */
	if (index != 0 || num != 1) {
		_ODP_ERR("Only single segment supported (%u, %u)\n", index, num);
		return -1;
	}

	if (odp_shm_info(shm, &info)) {
		_ODP_ERR("SHM info call failed\n");
		return -1;
	}

	seg_info[0].addr = (uintptr_t)info.addr;
	seg_info[0].iova = ODP_SHM_IOVA_INVALID;
	seg_info[0].pa   = ODP_SHM_PA_INVALID;
	seg_info[0].len  = info.size;

	return 0;
}

void odp_shm_print_all(void)
{
	_odp_ishm_status("ODP shared memory allocation status:");
}

void odp_shm_print(odp_shm_t shm)
{
	_odp_ishm_print(from_handle(shm));
}

uint64_t odp_shm_to_u64(odp_shm_t hdl)
{
	return _odp_pri(hdl);
}
