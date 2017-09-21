/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ODP_PACKET_SUBSYSTEM_H_
#define ODP_PACKET_SUBSYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_module.h>
#include <odp/api/packet.h>

#define PACKET_SUBSYSTEM_VERSION 0x00010000UL

/* ODP packet public APIs subsystem */
ODP_SUBSYSTEM_DECLARE(packet);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(packet, odp_packet_t, alloc, odp_pool_t pool,
		  uint32_t len);
ODP_SUBSYSTEM_API(packet, int, alloc_multi, odp_pool_t pool,
		  uint32_t len, odp_packet_t pkt[], int num);
ODP_SUBSYSTEM_API(packet, void, free, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, free_multi, const odp_packet_t pkt[], int num);
ODP_SUBSYSTEM_API(packet, int, has_error, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, prefetch, odp_packet_t pkt,
		  uint32_t offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, void *, data, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, input_index, odp_packet_t pkt);

typedef ODP_MODULE_CLASS(packet) {
	odp_module_base_t base;

	odp_api_proto(packet, alloc_multi) packet_alloc_multi ODP_ALIGNED_CACHE;
	odp_api_proto(packet, free_multi) packet_free_multi;
	odp_api_proto(packet, has_error) packet_has_error;
	odp_api_proto(packet, prefetch) packet_prefetch;
	odp_api_proto(packet, data) packet_data;
	odp_api_proto(packet, input_index) packet_input_index;
	odp_api_proto(packet, alloc) packet_alloc;
	odp_api_proto(packet, free) packet_free;
} odp_packet_module_t;

#ifdef __cplusplus
}
#endif

#endif

