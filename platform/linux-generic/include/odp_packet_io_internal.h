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
#include <odp_debug_internal.h>

#include <odp/config.h>
#include <odp/hints.h>
#include <net/if.h>

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
	int cls_enabled;		/**< is classifier enabled */
	odp_pktio_t handle;		/**< pktio handle */
	odp_queue_t inq_default;	/**< default input queue, if set */
	odp_queue_t outq_default;	/**< default out queue */
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_pktio_type_t type;		/**< pktio type */
	pkt_sock_t pkt_sock;		/**< using socket API for IO */
	pkt_sock_mmap_t pkt_sock_mmap;	/**< using socket mmap API for IO */
	classifier_t cls;		/**< classifier linked with this pktio*/
	char name[IF_NAMESIZE];		/**< name of pktio provided to
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

static inline int pktio_to_id(odp_pktio_t pktio)
{
	return _odp_typeval(pktio) - 1;
}

static inline pktio_entry_t *get_pktio_entry(odp_pktio_t pktio)
{
	if (odp_unlikely(pktio == ODP_PKTIO_INVALID))
		return NULL;

	if (odp_unlikely(_odp_typeval(pktio) > ODP_CONFIG_PKTIO_ENTRIES)) {
		ODP_DBG("pktio limit %d/%d exceed\n",
			_odp_typeval(pktio), ODP_CONFIG_PKTIO_ENTRIES);
		return NULL;
	}

	return pktio_entry_ptr[pktio_to_id(pktio)];
}

int pktin_poll(pktio_entry_t *entry);

int loopback_init(pktio_entry_t *pktio_entry, odp_pktio_t id);
int loopback_close(pktio_entry_t *pktio_entry);
int loopback_recv_pkt(pktio_entry_t *pktio_entry, odp_packet_t pkts[],
		      unsigned len);
int loopback_send_pkt(pktio_entry_t *pktio_entry, odp_packet_t pkt_tbl[],
		      unsigned len);
int loopback_mtu_get(pktio_entry_t *pktio_entry);
int loopback_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr);
int loopback_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable);
int loopback_promisc_mode_get(pktio_entry_t *pktio_entry);

int sock_mtu_get(pktio_entry_t *pktio_entry);

int sock_mmap_mtu_get(pktio_entry_t *pktio_entry);

int sock_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr);

int sock_mmap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr);

int sock_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable);

int sock_mmap_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable);

#ifdef __cplusplus
}
#endif

#endif
