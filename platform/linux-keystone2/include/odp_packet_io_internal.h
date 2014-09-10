/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_INTERNAL_H_
#define ODP_PACKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_spinlock.h>
#include <odp_packet_socket.h>
#include <ti/drv/nwal/nwal.h>
#include <ti/drv/nwal/nwal_util.h>

struct pktio_entry {
	odp_spinlock_t lock;		 /**< entry spinlock */
	int taken;			 /**< is entry taken(1) or free(0) */
	odp_queue_t inq_default;	 /**< default input queue, if set */
	odp_queue_t outq_default;	 /**< default out queue */
	odp_buffer_pool_t in_pool;       /**< pool for incoming packets */
	odp_pktio_t id;                  /**< pktio handle */
	nwalTxPSCmdInfo_t tx_ps_cmdinfo; /**< saved Command Label */
	int port;                        /**< netcp port number */
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

#ifdef __cplusplus
}
#endif

#endif
