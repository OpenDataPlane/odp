/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_BUFFER_SUBSYSTEM_H_
#define ODP_BUFFER_SUBSYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_module.h>
#include <odp/api/buffer.h>

#define BUFFER_SUBSYSTEM_VERSION 0x00010000UL

/* ODP buffer public APIs subsystem */
ODP_SUBSYSTEM_DECLARE(buffer);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(buffer, odp_buffer_t, buffer_from_event, odp_event_t ev);
ODP_SUBSYSTEM_API(buffer, odp_event_t, buffer_to_event, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, void *, buffer_addr, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, uint32_t, buffer_size, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, int, buffer_is_valid, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, odp_pool_t, buffer_pool, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, odp_buffer_t, buffer_alloc, odp_pool_t pool_hdl);
ODP_SUBSYSTEM_API(buffer, int, buffer_alloc_multi, odp_pool_t pool_hdl,
		  odp_buffer_t buf[], int num);
ODP_SUBSYSTEM_API(buffer, void, buffer_free, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, void, buffer_free_multi,
		  const odp_buffer_t buf[], int num);
ODP_SUBSYSTEM_API(buffer, void, buffer_print, odp_buffer_t buf);
ODP_SUBSYSTEM_API(buffer, uint64_t, buffer_to_u64, odp_buffer_t hdl);

typedef ODP_MODULE_CLASS(buffer) {
	odp_module_base_t base;

	odp_api_proto(buffer, buffer_from_event) buffer_from_event;
	odp_api_proto(buffer, buffer_to_event) buffer_to_event;
	odp_api_proto(buffer, buffer_addr) buffer_addr;
	odp_api_proto(buffer, buffer_alloc_multi) buffer_alloc_multi;
	odp_api_proto(buffer, buffer_free_multi) buffer_free_multi;
	odp_api_proto(buffer, buffer_alloc) buffer_alloc;
	odp_api_proto(buffer, buffer_free) buffer_free;
	odp_api_proto(buffer, buffer_size) buffer_size;
	odp_api_proto(buffer, buffer_is_valid) buffer_is_valid;
	odp_api_proto(buffer, buffer_pool) buffer_pool;
	odp_api_proto(buffer, buffer_print) buffer_print;
	odp_api_proto(buffer, buffer_to_u64) buffer_to_u64;
} odp_buffer_module_t;

#ifdef __cplusplus
}
#endif

#endif

