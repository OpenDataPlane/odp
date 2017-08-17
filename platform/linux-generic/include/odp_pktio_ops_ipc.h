/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_OPS_IPC_H_
#define ODP_PKTIO_OPS_IPC_H_

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
		char pool_name[ODP_POOL_NAME_LEN];
		/* 1 if master finished creation of all shared objects */
		int init_done;
	} master;
	struct {
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

typedef	struct {
	/* TX */
	struct  {
		_ring_t	*send; /**< ODP ring for IPC msg packets
					    indexes transmitted to shared
					    memory */
		_ring_t	*free; /**< ODP ring for IPC msg packets
					    indexes already processed by remote
					    process */
	} tx;
	/* RX */
	struct {
		_ring_t	*recv; /**< ODP ring for IPC msg packets
					    indexes received from shared
					     memory (from remote process) */
		_ring_t	*free; /**< odp ring for ipc msg packets
					    indexes already processed by
					    current process */
		_ring_t	*cache; /**< local cache to keep packet order right */
	} rx; /* slave */
	void		*pool_base;		/**< Remote pool base addr */
	void		*pool_mdata_base;	/**< Remote pool mdata base addr */
	uint64_t	pkt_size;		/**< Packet size in remote pool */
	odp_pool_t	pool;			/**< Pool of main process */
	enum {
		PKTIO_TYPE_IPC_MASTER = 0, /**< Master is the process which
						creates shm */
		PKTIO_TYPE_IPC_SLAVE	   /**< Slave is the process which
						connects to shm */
	} type; /**< define if it's master or slave process */
	odp_atomic_u32_t ready; /**< 1 - pktio is ready and can recv/send
				     packet, 0 - not yet ready */
	void *pinfo;
	odp_shm_t pinfo_shm;
	odp_shm_t remote_pool_shm; /**< shm of remote pool get with
					_ipc_map_remote_pool() */
} pktio_ops_ipc_data_t;

#endif
