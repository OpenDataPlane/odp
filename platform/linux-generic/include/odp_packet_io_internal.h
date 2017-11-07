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

#include <config.h>

#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <odp_queue_if.h>

#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <net/if.h>

#define PKTIO_MAX_QUEUES 64
/* Forward declaration */
typedef struct pktio_entry odp_pktio_entry_t;
#include <odp_pktio_ops_subsystem.h>

#define PKTIO_NAME_LEN 256

#define PKTIN_INVALID  ((odp_pktin_queue_t) {ODP_PKTIO_INVALID, 0})
#define PKTOUT_INVALID ((odp_pktout_queue_t) {ODP_PKTIO_INVALID, 0})

struct pktio_entry {
	const pktio_ops_module_t *ops;	/**< Implementation specific methods */
	uint8_t ops_data[ODP_PKTIO_ODPS_DATA_MAX_SIZE]; /**< IO operation
							specific data */
	/* These two locks together lock the whole pktio device */
	odp_ticketlock_t rxl;		/**< RX ticketlock */
	odp_ticketlock_t txl;		/**< TX ticketlock */
	int cls_enabled;		/**< is classifier enabled */
	odp_pktio_t handle;		/**< pktio handle */
	enum {
		/* Not allocated */
		PKTIO_STATE_FREE = 0,
		/* Close pending on scheduler response. Next state after this
		 * is PKTIO_STATE_FREE. */
		PKTIO_STATE_CLOSE_PENDING,
		/* Open in progress.
		   Marker for all active states following under. */
		PKTIO_STATE_ACTIVE,
		/* Open completed */
		PKTIO_STATE_OPENED,
		/* Start completed */
		PKTIO_STATE_STARTED,
		/* Stop pending on scheduler response */
		PKTIO_STATE_STOP_PENDING,
		/* Stop completed */
		PKTIO_STATE_STOPPED
	} state;
	odp_pktio_config_t config;	/**< Device configuration */
	classifier_t cls;		/**< classifier linked with this pktio*/
	odp_pktio_stats_t stats;	/**< statistic counters for pktio */
	enum {
		STATS_SYSFS = 0,
		STATS_ETHTOOL,
		STATS_UNSUPPORTED
	} stats_type;
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
		queue_t            queue_int;
		odp_pktin_queue_t  pktin;
	} in_queue[PKTIO_MAX_QUEUES];

	struct {
		odp_queue_t        queue;
		odp_pktout_queue_t pktout;
	} out_queue[PKTIO_MAX_QUEUES];
};

typedef union pktio_entry_u {
	odp_pktio_entry_t s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(odp_pktio_entry_t))];
} pktio_entry_t;

#define ODP_PKTIO_ENTRY(_p) ((odp_pktio_entry_t *)(uintptr_t)_p)

typedef struct {
	odp_spinlock_t lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

extern void *pktio_entry_ptr[];

static inline int pktio_to_id(odp_pktio_t pktio)
{
	return _odp_typeval(pktio) - 1;
}

static inline odp_pktio_entry_t *get_pktio_entry(odp_pktio_t pktio)
{
	if (odp_unlikely(pktio == ODP_PKTIO_INVALID))
		return NULL;

	if (odp_unlikely(_odp_typeval(pktio) > ODP_CONFIG_PKTIO_ENTRIES)) {
		ODP_DBG("pktio limit %d/%d exceed\n",
			_odp_typeval(pktio), ODP_CONFIG_PKTIO_ENTRIES);
		return NULL;
	}

	return ODP_PKTIO_ENTRY(pktio_entry_ptr[pktio_to_id(pktio)]);
}

static inline int pktio_cls_enabled(odp_pktio_entry_t *entry)
{
	return entry->cls_enabled;
}

static inline void pktio_cls_enabled_set(odp_pktio_entry_t *entry, int ena)
{
	entry->cls_enabled = ena;
}

int pktin_poll_one(int pktio_index,
		   int rx_queue,
		   odp_event_t evt_tbl[]);
int pktin_poll(int pktio_index, int num_queue, int index[]);
void pktio_stop_finalize(int pktio_index);

#ifdef __cplusplus
}
#endif

#endif
