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

#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>

#include <odp_config_internal.h>
#include <odp/api/hints.h>

#define PKTIO_MAX_QUEUES 64
#include <linux/if_ether.h>
#include <odp_packet_dpdk.h>

#define PKTIO_NAME_LEN 256

#define PKTIN_INVALID  ((odp_pktin_queue_t) {ODP_PKTIO_INVALID, 0})
#define PKTOUT_INVALID ((odp_pktout_queue_t) {ODP_PKTIO_INVALID, 0})

/* Forward declaration */
struct pktio_if_ops;
struct pkt_dpdk_t;

typedef struct {
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_bool_t promisc;		/**< promiscuous mode state */
} pkt_loop_t;

/** Packet socket using dpdk mmaped rings for both Rx and Tx */
typedef struct {
	odp_pktio_capability_t	capa;	  /**< interface capabilities */

	/********************************/
	char ifname[32];
	uint8_t min_rx_burst;
	uint8_t portid;
	odp_bool_t vdev_sysc_promisc;	/**< promiscuous mode defined with
					    system call */
	odp_pktin_hash_proto_t hash;	  /**< Packet input hash protocol */
	odp_bool_t lockless_rx;		  /**< no locking for rx */
	odp_bool_t lockless_tx;		  /**< no locking for tx */
	odp_ticketlock_t rx_lock[PKTIO_MAX_QUEUES];  /**< RX queue locks */
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES];  /**< TX queue locks */
} pkt_dpdk_t;

struct pktio_entry {
	const struct pktio_if_ops *ops; /**< Implementation specific methods */
	/* These two locks together lock the whole pktio device */
	odp_ticketlock_t rxl;		/**< RX ticketlock */
	odp_ticketlock_t txl;		/**< TX ticketlock */
	int cls_enabled;		/**< is classifier enabled */
	odp_pktio_t handle;		/**< pktio handle */
	union {
		pkt_loop_t pkt_loop;	/**< Using loopback for IO */
		pkt_dpdk_t pkt_dpdk;	/**< using DPDK API for IO */
	};
	enum {
		PKTIO_STATE_FREE = 0,     /**< Not allocated */
		PKTIO_STATE_ALLOCATED,    /**< Allocated, open in progress */
		PKTIO_STATE_OPENED,       /**< Open completed */
		PKTIO_STATE_STARTED,      /**< Start completed */
		PKTIO_STATE_STOPPED       /**< Stop completed */
	} state;
	odp_pktio_config_t config;	/**< Device configuration */
	classifier_t cls;		/**< classifier linked with this pktio*/
	odp_pktio_stats_t stats;	/**< statistic counters for pktio */
	char name[PKTIO_NAME_LEN];	/**< name of pktio provided to
					   pktio_open() */
	odp_pool_t pool;
	odp_pktio_param_t param;

	/* Storage for queue handles
	 * Multi-queue support is pktio driver specific */
	unsigned num_in_queue;
	unsigned num_out_queue;

	struct {
		odp_queue_t        queue;
		odp_pktin_queue_t  pktin;
	} in_queue[PKTIO_MAX_QUEUES];

	struct {
		odp_queue_t        queue;
		odp_pktout_queue_t pktout;
	} out_queue[PKTIO_MAX_QUEUES];
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

typedef struct {
	odp_spinlock_t lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

typedef struct pktio_if_ops {
	const char *name;
	void (*print)(pktio_entry_t *pktio_entry);
	int (*init_global)(void);
	int (*init_local)(void);
	int (*term)(void);
	int (*open)(odp_pktio_t pktio, pktio_entry_t *pktio_entry,
		    const char *devname, odp_pool_t pool);
	int (*close)(pktio_entry_t *pktio_entry);
	int (*start)(pktio_entry_t *pktio_entry);
	int (*stop)(pktio_entry_t *pktio_entry);
	int (*stats)(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats);
	int (*stats_reset)(pktio_entry_t *pktio_entry);
	uint64_t (*pktin_ts_res)(pktio_entry_t *pktio_entry);
	odp_time_t (*pktin_ts_from_ns)(pktio_entry_t *pktio_entry, uint64_t ns);
	int (*recv)(pktio_entry_t *entry, int index, odp_packet_t packets[],
		    int num);
	int (*send)(pktio_entry_t *entry, int index,
		    const odp_packet_t packets[], int num);
	uint32_t (*mtu_get)(pktio_entry_t *pktio_entry);
	int (*promisc_mode_set)(pktio_entry_t *pktio_entry,  int enable);
	int (*promisc_mode_get)(pktio_entry_t *pktio_entry);
	int (*mac_get)(pktio_entry_t *pktio_entry, void *mac_addr);
	int (*link_status)(pktio_entry_t *pktio_entry);
	int (*capability)(pktio_entry_t *pktio_entry,
			  odp_pktio_capability_t *capa);
	int (*config)(pktio_entry_t *pktio_entry,
		      const odp_pktio_config_t *config);
	int (*input_queues_config)(pktio_entry_t *pktio_entry,
				   const odp_pktin_queue_param_t *param);
	int (*output_queues_config)(pktio_entry_t *pktio_entry,
				    const odp_pktout_queue_param_t *p);
} pktio_if_ops_t;

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

static inline int pktio_cls_enabled(pktio_entry_t *entry)
{
	return entry->s.cls_enabled;
}

static inline void pktio_cls_enabled_set(pktio_entry_t *entry, int ena)
{
	entry->s.cls_enabled = ena;
}

/*
 * Dummy single queue implementations of multi-queue API
 */
int single_capability(odp_pktio_capability_t *capa);
int single_input_queues_config(pktio_entry_t *entry,
			       const odp_pktin_queue_param_t *param);
int single_output_queues_config(pktio_entry_t *entry,
				const odp_pktout_queue_param_t *param);
int single_recv_queue(pktio_entry_t *entry, int index, odp_packet_t packets[],
		      int num);
int single_send_queue(pktio_entry_t *entry, int index,
		      const odp_packet_t packets[], int num);

extern const pktio_if_ops_t loopback_pktio_ops;
extern const pktio_if_ops_t dpdk_pktio_ops;
extern const pktio_if_ops_t * const pktio_if_ops[];

#ifdef __cplusplus
}
#endif

#endif
