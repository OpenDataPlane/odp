/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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

#include <odp/autoheader_internal.h>

#include <odp/api/packet_io.h>
#include <odp/api/plat/pktio_inlines.h>
#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_io_ring_internal.h>
#include <odp_packet_io_stats_common.h>
#include <odp_queue_if.h>

#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/select.h>

#define PKTIO_MAX_QUEUES 64

#define PKTIO_NAME_LEN 256

#define PKTIN_INVALID  ((odp_pktin_queue_t) {ODP_PKTIO_INVALID, 0})
#define PKTOUT_INVALID ((odp_pktout_queue_t) {ODP_PKTIO_INVALID, 0})

/** Determine if a socket read/write error should be reported. Transient errors
 *  that simply require the caller to retry are ignored, the _send/_recv APIs
 *  are non-blocking and it is the caller's responsibility to retry if the
 *  requested number of packets were not handled. */
#define SOCK_ERR_REPORT(e) (e != EAGAIN && e != EWOULDBLOCK && e != EINTR)

/* Forward declaration */
struct pktio_if_ops;

#if defined(_ODP_PKTIO_NETMAP)
#define PKTIO_PRIVATE_SIZE 74752
#elif defined(_ODP_PKTIO_DPDK) && ODP_CACHE_LINE_SIZE == 128
#define PKTIO_PRIVATE_SIZE 10240
#elif defined(_ODP_PKTIO_DPDK)
#define PKTIO_PRIVATE_SIZE 5632
#else
#define PKTIO_PRIVATE_SIZE 384
#endif

struct pktio_entry {
	const struct pktio_if_ops *ops; /**< Implementation specific methods */
	/* These two locks together lock the whole pktio device */
	odp_ticketlock_t rxl;		/**< RX ticketlock */
	odp_ticketlock_t txl;		/**< TX ticketlock */
	uint8_t cls_enabled;            /**< classifier enabled */
	uint8_t chksum_insert_ena;      /**< pktout checksum offload enabled */
	odp_pktio_t handle;		/**< pktio handle */
	unsigned char ODP_ALIGNED_CACHE pkt_priv[PKTIO_PRIVATE_SIZE];
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
	odp_proto_chksums_t in_chksums; /**< Checksums validation settings */
	pktio_stats_type_t stats_type;
	char name[PKTIO_NAME_LEN];	/**< name of pktio provided to
					     internal pktio_open() calls */
	char full_name[PKTIO_NAME_LEN];	/**< original pktio name passed to
					     odp_pktio_open() and returned by
					     odp_pktio_info() */
	odp_pool_t pool;
	odp_pktio_param_t param;
	odp_pktio_capability_t capa;	/**< Packet IO capabilities */

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

	/**< inotify instance for pcapng fifos */
	struct {
		enum {
			PCAPNG_WR_STOP = 0,
			PCAPNG_WR_PKT,
		} state[PKTIO_MAX_QUEUES];
		int fd[PKTIO_MAX_QUEUES];
	} pcapng;
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pktio_entry))];
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
	int (*recv_tmo)(pktio_entry_t *entry, int index, odp_packet_t packets[],
			int num, uint64_t wait_usecs);
	int (*recv_mq_tmo)(pktio_entry_t *entry[], int index[], int num_q,
			   odp_packet_t packets[], int num, unsigned *from,
			   uint64_t wait_usecs);
	int (*fd_set)(pktio_entry_t *entry, int index, fd_set *readfds);
	int (*send)(pktio_entry_t *entry, int index,
		    const odp_packet_t packets[], int num);
	uint32_t (*mtu_get)(pktio_entry_t *pktio_entry);
	int (*promisc_mode_set)(pktio_entry_t *pktio_entry,  int enable);
	int (*promisc_mode_get)(pktio_entry_t *pktio_entry);
	int (*mac_get)(pktio_entry_t *pktio_entry, void *mac_addr);
	int (*mac_set)(pktio_entry_t *pktio_entry, const void *mac_addr);
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

static inline pktio_entry_t *get_pktio_entry(odp_pktio_t pktio)
{
	int idx;

	if (odp_unlikely(pktio == ODP_PKTIO_INVALID))
		return NULL;

	if (odp_unlikely(_odp_typeval(pktio) > ODP_CONFIG_PKTIO_ENTRIES)) {
		ODP_DBG("pktio limit %d/%d exceed\n",
			_odp_typeval(pktio), ODP_CONFIG_PKTIO_ENTRIES);
		return NULL;
	}

	idx = odp_pktio_index(pktio);

	return pktio_entry_ptr[idx];
}

static inline int pktio_cls_enabled(pktio_entry_t *entry)
{
	return entry->s.cls_enabled;
}

static inline void pktio_cls_enabled_set(pktio_entry_t *entry, int ena)
{
	entry->s.cls_enabled = ena;
}

extern const pktio_if_ops_t netmap_pktio_ops;
extern const pktio_if_ops_t dpdk_pktio_ops;
extern const pktio_if_ops_t sock_mmsg_pktio_ops;
extern const pktio_if_ops_t sock_mmap_pktio_ops;
extern const pktio_if_ops_t loopback_pktio_ops;
#ifdef _ODP_PKTIO_PCAP
extern const pktio_if_ops_t pcap_pktio_ops;
#endif
extern const pktio_if_ops_t tap_pktio_ops;
extern const pktio_if_ops_t null_pktio_ops;
extern const pktio_if_ops_t ipc_pktio_ops;
extern const pktio_if_ops_t * const pktio_if_ops[];

/**
 * Try interrupt-driven receive
 *
 * @param queues Pktin queues
 * @param num_q Number of queues
 * @param packets Output packet slots
 * @param num Number of output packet slots
 * @param from Queue from which the call received packets
 * @param usecs Microseconds to wait
 * @param trial_successful Will receive information whether trial was successful
 *
 * @return >=0 on success, number of packets received
 * @return <0 on failure
 */
int sock_recv_mq_tmo_try_int_driven(const struct odp_pktin_queue_t queues[],
				    unsigned num_q, unsigned *from,
				    odp_packet_t packets[], int num,
				    uint64_t usecs,
				    int *trial_successful);

#ifdef __cplusplus
}
#endif

#endif
