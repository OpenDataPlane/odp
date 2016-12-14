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
		/* number of buffer*/
		int num;
		/* size of packet/segment in remote pool */
		uint32_t block_size;
		/* offset from shared memory block start
		 * to pool *base_addr in remote process.
		 * (odp-linux pool specific) */
		size_t base_addr_offset;
		char pool_name[ODP_POOL_NAME_LEN];
		/* 1 if master finished creation of all shared objects */
		int init_done;
	} master;
	struct {
		/* offset from shared memory block start
		 * to pool *base_addr in remote process.
		 * (odp-linux pool specific) */
		size_t base_addr_offset;
		void *base_addr;
		uint32_t block_size;
		char pool_name[ODP_POOL_NAME_LEN];
		/* pid of the slave process written to shm and
		 * used by master to look up memory created by
		 * slave
		 */
		int pid;
		int init_done;
	} slave;
} ODP_PACKED;
