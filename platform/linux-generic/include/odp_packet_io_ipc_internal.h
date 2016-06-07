/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* IPC packet I/O over shared memory ring */
#include <odp_packet_io_ring_internal.h>

/* number of odp buffers in odp ring queue */
#define PKTIO_IPC_ENTRIES 4096

/* that struct is exported to shared memory, so that processes can find
 * each other.
 */
struct pktio_info {
	struct {
		/* number of buffer in remote pool */
		int shm_pool_bufs_num;
		/* size of remote pool */
		size_t shm_pkt_pool_size;
		/* size of packet/segment in remote pool */
		uint32_t shm_pkt_size;
		/* offset from shared memory block start
		 * to pool_mdata_addr (odp-linux pool specific) */
		size_t mdata_offset;
		char pool_name[ODP_POOL_NAME_LEN];
	} master;
	struct {
		/* offset from shared memory block start
		 * to pool_mdata_addr in remote process.
		 * (odp-linux pool specific) */
		size_t mdata_offset;
		char pool_name[ODP_POOL_NAME_LEN];
	} slave;
} ODP_PACKED;
