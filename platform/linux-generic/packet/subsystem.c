/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <odp_packet_subsystem.h>
#include <odp_module.h>

ODP_SUBSYSTEM_DEFINE(packet, "packet public APIs",
		     PACKET_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(packet)
{
	odp_subsystem_constructor(packet);
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_alloc(pool_hdl, len);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int max_num)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_alloc_multi(pool_hdl, len, pkt, max_num);
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_free(pkt);
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_free_multi(pkt, num);
}

int odp_packet_has_error(odp_packet_t pkt)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_has_error(pkt);
}

void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_prefetch(pkt, offset, len);
}

void *odp_packet_data(odp_packet_t pkt)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_data(pkt);
}

int odp_packet_input_index(odp_packet_t pkt)
{
	odp_packet_module_t *mod;

	mod = odp_subsystem_active_module(packet, mod);
	return mod->packet_input_index(pkt);
}

