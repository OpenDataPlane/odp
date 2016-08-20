/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_config_internal.h>
#include <odp/api/std_types.h>
#include <odp/drv/shm.h>
#include <_ishm_internal.h>

static inline uint32_t from_handle(odpdrv_shm_t shm)
{
	return _odpdrv_typeval(shm) - 1;
}

static inline odpdrv_shm_t to_handle(uint32_t index)
{
	return _odpdrv_cast_scalar(odpdrv_shm_t, index + 1);
}

int odpdrv_shm_capability(odpdrv_shm_capability_t *capa)
{
	capa->max_blocks = ODPDRV_CONFIG_SHM_BLOCKS;
	capa->max_size = 0;
	capa->max_align = 0;

	return 0;
}

odpdrv_shm_t odpdrv_shm_reserve(const char *name, uint64_t size, uint64_t align,
				uint32_t flags)
{
	int block_index;
	int flgs = 0; /* internal ishm flags */

	/* set internal ishm flags according to API flags: */
	flgs |= (flags & ODPDRV_SHM_SINGLE_VA) ? _ODP_ISHM_SINGLE_VA : 0;
	flgs |= (flags & ODPDRV_SHM_LOCK) ? _ODP_ISHM_LOCK : 0;

	block_index = _odp_ishm_reserve(name, size, -1, align, flgs, flags);
	if (block_index >= 0)
		return to_handle(block_index);
	else
		return ODPDRV_SHM_INVALID;
}

int odpdrv_shm_free_by_handle(odpdrv_shm_t shm)
{
	return _odp_ishm_free_by_index(from_handle(shm));
}

int odpdrv_shm_free_by_name(const char *name)
{
	return _odp_ishm_free_by_name(name);
}

int odpdrv_shm_free_by_address(void *address)
{
	return _odp_ishm_free_by_address(address);
}

void *odpdrv_shm_lookup_by_handle(odpdrv_shm_t shm)
{
	return _odp_ishm_lookup_by_index(from_handle(shm));
}

odpdrv_shm_t odpdrv_shm_lookup_by_name(const char *name)
{
	return to_handle(_odp_ishm_lookup_by_name(name));
}

odpdrv_shm_t odpdrv_shm_lookup_by_address(void *address)
{
	return to_handle(_odp_ishm_lookup_by_address(address));
}

void *odpdrv_shm_addr(odpdrv_shm_t shm)
{
	return _odp_ishm_address(from_handle(shm));
}

int odpdrv_shm_info(odpdrv_shm_t shm, odpdrv_shm_info_t *info)
{
	_odp_ishm_info_t ishm_info;

	if (_odp_ishm_info(from_handle(shm), &ishm_info))
		return -1;

	info->name = ishm_info.name;
	info->addr = ishm_info.addr;
	info->size = ishm_info.size;
	info->page_size = ishm_info.page_size;
	info->flags = ishm_info.user_flags;

	return 0;
}

int odpdrv_shm_print_all(const char *title)
{
	return _odp_ishm_status(title);
}
