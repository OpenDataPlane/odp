/* Copyright (c) 2013, Linaro Limited
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

#include <odp/spinlock.h>
#include <odp_packet_socket.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>

#include <odp/config.h>
#include <odp/hints.h>
#include <linux/if.h>

/**
 * Packet IO types
 */
typedef enum {
	ODP_PKTIO_TYPE_SOCKET_BASIC = 0x1,
	ODP_PKTIO_TYPE_SOCKET_MMSG,
	ODP_PKTIO_TYPE_SOCKET_MMAP,
	ODP_PKTIO_TYPE_LOOPBACK,
} odp_pktio_type_t;

struct pktio_entry {
	odp_spinlock_t lock;		/**< entry spinlock */
	int taken;			/**< is entry taken(1) or free(0) */
	odp_queue_t inq_default;	/**< default input queue, if set */
	odp_queue_t outq_default;	/**< default out queue */
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_pktio_type_t type;		/**< pktio type */
	pkt_sock_t pkt_sock;		/**< using socket API for IO */
	pkt_sock_mmap_t pkt_sock_mmap;	/**< using socket mmap API for IO */
	classifier_t cls;		/**< classifier linked with this pktio*/
	char name[IFNAMSIZ];		/**< name of pktio provided to
					   pktio_open() */
	odp_bool_t promisc;		/**< promiscuous mode state */
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

typedef struct {
	odp_spinlock_t lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

extern void *pktio_entry_ptr[];


static inline pktio_entry_t *get_pktio_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 id > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return pktio_entry_ptr[id - 1];
}
#ifdef __cplusplus
}
#endif

#endif
