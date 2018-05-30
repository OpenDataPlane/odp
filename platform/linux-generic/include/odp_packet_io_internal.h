/* Copyright (c) 2013-2018, Linaro Limited
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

#include <odp/api/packet_io.h>
#include <odp/api/plat/pktio_inlines.h>
#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_io_ring_internal.h>
#include <odp_queue_if.h>

#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <net/if.h>

#define PKTIO_MAX_QUEUES 64
#include <odp_packet_socket.h>
#include <odp_packet_netmap.h>
#include <odp_packet_tap.h>
#include <odp_packet_null.h>
#include <odp_packet_dpdk.h>

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

typedef struct {
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_bool_t promisc;		/**< promiscuous mode state */
	uint8_t idx;			/**< index of "loop" device */
} pkt_loop_t;

#ifdef HAVE_PCAP
typedef struct {
	char *fname_rx;		/**< name of pcap file for rx */
	char *fname_tx;		/**< name of pcap file for tx */
	void *rx;		/**< rx pcap handle */
	void *tx;		/**< tx pcap handle */
	void *tx_dump;		/**< tx pcap dumper handle */
	odp_pool_t pool;	/**< rx pool */
	unsigned char *buf;	/**< per-pktio temp buffer */
	int loops;		/**< number of times to loop rx pcap */
	int loop_cnt;		/**< number of loops completed */
	odp_bool_t promisc;	/**< promiscuous mode state */
} pkt_pcap_t;
#endif

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
} _ipc_pktio_t;

#define PKTIO_PRIVATE_SIZE 384

struct pktio_entry {
	const struct pktio_if_ops *ops; /**< Implementation specific methods */
	/* These two locks together lock the whole pktio device */
	odp_ticketlock_t rxl;		/**< RX ticketlock */
	odp_ticketlock_t txl;		/**< TX ticketlock */
	uint8_t cls_enabled;            /**< classifier enabled */
	uint8_t chksum_insert_ena;      /**< pktout checksum offload enabled */
	odp_pktio_t handle;		/**< pktio handle */
	union {
		pkt_loop_t pkt_loop;            /**< Using loopback for IO */
		pkt_sock_t pkt_sock;		/**< using socket API for IO */
		pkt_sock_mmap_t pkt_sock_mmap;	/**< using socket mmap
						 *   API for IO */
		pkt_netmap_t pkt_nm;		/**< using netmap API for IO */
		pkt_dpdk_t pkt_dpdk;		/**< using DPDK for IO */
#ifdef HAVE_PCAP
		pkt_pcap_t pkt_pcap;		/**< Using pcap for IO */
#endif
		pkt_tap_t pkt_tap;		/**< using TAP for IO */
		_ipc_pktio_t ipc;		/**< IPC pktio data */
		pkt_null_t pkt_null;		/**< using null for IO */
		unsigned char ODP_ALIGNED_CACHE pkt_priv[PKTIO_PRIVATE_SIZE];
	};
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
	enum {
		STATS_SYSFS = 0,
		STATS_ETHTOOL,
		STATS_UNSUPPORTED
	} stats_type;
	char name[PKTIO_NAME_LEN];	/**< name of pktio provided to
					   pktio_open() */

	odp_pool_t pool;
	odp_pktio_param_t param;
	odp_pktio_capability_t capa;	/**< Packet IO capabilities */

	/* Storage for queue handles
	 * Multi-queue support is pktio driver specific */
	unsigned num_in_queue;
	unsigned num_out_queue;

	struct {
		odp_queue_t        queue;
		void              *queue_int;
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
#ifdef HAVE_PCAP
extern const pktio_if_ops_t pcap_pktio_ops;
#endif
extern const pktio_if_ops_t tap_pktio_ops;
extern const pktio_if_ops_t null_pktio_ops;
extern const pktio_if_ops_t ipc_pktio_ops;
extern const pktio_if_ops_t * const pktio_if_ops[];

int sysfs_stats(pktio_entry_t *pktio_entry,
		odp_pktio_stats_t *stats);
int sock_stats_fd(pktio_entry_t *pktio_entry,
		  odp_pktio_stats_t *stats,
		  int fd);
int sock_stats_reset_fd(pktio_entry_t *pktio_entry, int fd);

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
