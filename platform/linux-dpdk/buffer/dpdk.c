/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <config.h>

#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_buffer_subsystem.h>
#include <odp_debug_internal.h>
#include <odp_pool_internal.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

static odp_buffer_t buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_t buffer;
	pool_entry_dp_t *pool_dp;

	ODP_ASSERT(odp_pool_to_entry_cp(pool_hdl)->params.type ==
							ODP_POOL_BUFFER ||
		   odp_pool_to_entry_cp(pool_hdl)->params.type ==
							ODP_POOL_TIMEOUT);

	pool_dp = odp_pool_to_entry_dp(pool_hdl);

	buffer = (odp_buffer_t)rte_ctrlmbuf_alloc(pool_dp->rte_mempool);

	if ((struct rte_mbuf *)buffer == NULL) {
		rte_errno = ENOMEM;
		return ODP_BUFFER_INVALID;
	}

	return buffer;
}

static odp_buffer_t dpdk_buffer_alloc(odp_pool_t pool_hdl)
{
	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	return buffer_alloc(pool_hdl);
}

static int dpdk_buffer_alloc_multi(odp_pool_t pool_hdl,
				   odp_buffer_t buf[],
				   int num)
{
	int i;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	for (i = 0; i < num; i++) {
		buf[i] = buffer_alloc(pool_hdl);
		if (buf[i] == ODP_BUFFER_INVALID)
			return rte_errno == ENOMEM ? i : -EINVAL;
	}
	return i;
}

static void dpdk_buffer_free(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)buf;

	rte_ctrlmbuf_free(mbuf);
}

static void dpdk_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)buf[i];

		rte_ctrlmbuf_free(mbuf);
	}
}

static odp_buffer_t dpdk_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

static odp_event_t dpdk_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

static void *dpdk_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	return hdr->mb.buf_addr;
}

static uint32_t dpdk_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);
	struct rte_mbuf *mbuf = (struct rte_mbuf *)hdr;

	return mbuf->buf_len;
}

int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	return hdr->type;
}

void _odp_buffer_type_set(odp_buffer_t buf, int type)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	hdr->type = type;
}

static int dpdk_buffer_is_valid(odp_buffer_t buf)
{
	/* We could call rte_mbuf_sanity_check, but that panics
	 * and aborts the program */
	return buf != ODP_BUFFER_INVALID;
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = buf_hdl_to_hdr(buf);

	len += snprintf(&str[len], n - len,
			"Buffer\n");
	len += snprintf(&str[len], n - len,
			"  pool         %p\n", hdr->mb.pool);
	len += snprintf(&str[len], n - len,
			"  phy_addr     %" PRIu64 "\n", hdr->mb.buf_physaddr);
	len += snprintf(&str[len], n - len,
			"  addr         %p\n",        hdr->mb.buf_addr);
	len += snprintf(&str[len], n - len,
			"  size         %u\n",        hdr->mb.buf_len);
	len += snprintf(&str[len], n - len,
			"  ref_count    %i\n",
			rte_mbuf_refcnt_read(&hdr->mb));
	len += snprintf(&str[len], n - len,
			"  odp type     %i\n",        hdr->type);

	return len;
}

static void dpdk_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len - 1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

static uint64_t dpdk_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}

static odp_pool_t dpdk_buffer_pool(odp_buffer_t buf)
{
	return buf_hdl_to_hdr(buf)->pool_hdl;
}

odp_buffer_module_t dpdk_buffer = {
	.base = {
		.name = "dpdk_buffer",
		.init_local = NULL,
		.term_local = NULL,
		.init_global = NULL,
		.term_global = NULL,
		},
	.buffer_alloc = dpdk_buffer_alloc,
	.buffer_alloc_multi = dpdk_buffer_alloc_multi,
	.buffer_free = dpdk_buffer_free,
	.buffer_free_multi = dpdk_buffer_free_multi,
	.buffer_from_event = dpdk_buffer_from_event,
	.buffer_to_event = dpdk_buffer_to_event,
	.buffer_addr = dpdk_buffer_addr,
	.buffer_size = dpdk_buffer_size,
	.buffer_is_valid = dpdk_buffer_is_valid,
	.buffer_print = dpdk_buffer_print,
	.buffer_to_u64 = dpdk_buffer_to_u64,
	.buffer_pool = dpdk_buffer_pool,
};

ODP_MODULE_CONSTRUCTOR(dpdk_buffer)
{
	odp_module_constructor(&dpdk_buffer);
	odp_subsystem_register_module(buffer, &dpdk_buffer);
}
