/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_buffer_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_align.h>
#include <odp_internal.h>
#include <odp_config.h>
#include <odp_hints.h>
#include <odp_debug.h>

#include <string.h>
#include <stdlib.h>

/**
 * @todo: Currently a number of HW descriptors is limited,
 *        so temporary limit max number of buffers per pool
 *        to be albe to run ODP example apps.
 *        Descriptor management have to be made more intelligent
 *        To remove this limitation.
 */
#define MAX_BUFS_PER_POOL	1024

int odp_buffer_pool_init_global(void)
{
	/* Pktlib initialized in mcsdk_global_init() */
	return 0;
}

odp_buffer_pool_t odp_buffer_pool_create(const char *name,
		void *base_addr ODP_UNUSED, uint64_t size,
		size_t buf_size, size_t buf_align,
		int buf_type ODP_UNUSED)
{
	Pktlib_HeapCfg heap_cfg;
	Pktlib_HeapHandle heap_handle;
	int num_bufs;
	int err_code;

	buf_size  = ODP_ALIGN_ROUNDUP(buf_size, buf_align);
	/*
	 * XXX: size is used only to get number of buffers.
	 * Memory is allocated for each buffer separately
	 */
	num_bufs  = size / buf_size;
	buf_size += odp_global->cfg.min_buf_headroom_size;
	buf_size  = ODP_CACHE_LINE_SIZE_ROUNDUP(buf_size);


	if (num_bufs > MAX_BUFS_PER_POOL) {
		odp_pr_dbg("Limiting number of buffer in %s from %d to %d\n",
			   name, num_bufs, MAX_BUFS_PER_POOL);
		num_bufs = MAX_BUFS_PER_POOL;
	}

	/* Initialize the heap configuration. */
	memset((void *)&heap_cfg, 0, sizeof(Pktlib_HeapCfg));
	/* Populate the heap configuration */
	heap_cfg.name               = name;
	heap_cfg.memRegion          = TUNE_NETAPI_QM_GLOBAL_REGION;
	heap_cfg.sharedHeap         = 1;
	heap_cfg.useStarvationQueue = 0;
	heap_cfg.dataBufferSize     = buf_size;
	heap_cfg.numPkts            = num_bufs;
	heap_cfg.numZeroBufferPackets   = 0;
	heap_cfg.heapInterfaceTable.data_malloc =
			pktlib_if_table.data_malloc;
	heap_cfg.heapInterfaceTable.data_free =
			pktlib_if_table.data_free;
	heap_cfg.dataBufferPktThreshold = 0;
	heap_cfg.zeroBufferPktThreshold = 0;
	odp_pr_dbg("name: %s, buf_size: %u, num_bufs: %u\n", name, buf_size,
		   num_bufs);
	/* Create Shared Heap with specified configuration. */
	heap_handle = Pktlib_createHeap(&heap_cfg, &err_code);
	odp_pr_dbg("heap_handle: %p, err_code: %d\n", heap_handle, err_code);
	return heap_handle;
}

odp_buffer_pool_t odp_buffer_pool_lookup(const char *name)
{
	return Pktlib_findHeapByName(name);
}

odp_buffer_t odp_buffer_alloc(odp_buffer_pool_t pool_id)
{
	Ti_Pkt *pkt;
	odp_buffer_t buf;
	Cppi_HostDesc *desc;

	pkt = Pktlib_allocPacket(pool_id, -1);
	if (!pkt)
		return ODP_BUFFER_INVALID;

	buf = _ti_pkt_to_odp_buf(pkt);
	desc = _odp_buf_to_cppi_desc(buf);

	/* Leave space for buffer metadata. There must be enough space. */
	desc->buffPtr = desc->origBuffPtr +
			odp_global->cfg.min_buf_headroom_size;

	odp_pr_vdbg("pool_id: %p, pkt: %p, buf: %p\n", pool_id, pkt, buf);
	return buf;
}

void odp_buffer_free(odp_buffer_t buf)
{
	odp_pr_vdbg("buf: %p\n", buf);
	Pktlib_freePacket(_odp_buf_to_ti_pkt(buf));
}

void odp_buffer_pool_print(odp_buffer_pool_t pool_id)
{
	(void)pool_id;
}

odp_buffer_pool_t odp_buf_to_pool(odp_buffer_t buf)
{
	return Pktlib_getPktHeap(_odp_buf_to_ti_pkt(buf));
}

uint32_t _odp_pool_get_free_queue(odp_buffer_pool_t pool_id)
{
	return Pktlib_getInternalHeapQueue(pool_id);
}
