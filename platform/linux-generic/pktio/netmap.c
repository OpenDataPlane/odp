/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_NETMAP

#include <odp_posix_extensions.h>

#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_io_stats.h>
#include <odp_ethtool_stats.h>
#include <odp_ethtool_rss.h>
#include <odp_socket_common.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <protocols/eth.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <poll.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <odp_classification_datamodel.h>
#include <odp_classification_internal.h>
#include <odp_libconfig_internal.h>

#include <inttypes.h>

/* Disable netmap debug prints */
#ifndef ND
#define ND(_fmt, ...) do {} while (0)
#define D(_fmt, ...) do {} while (0)
#define RD(lps, format, ...) do {} while (0)
#endif

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define NM_WAIT_TIMEOUT 10 /* netmap_wait_for_link() timeout in seconds */
#define NM_INJECT_RETRIES 10

#define NM_MAX_DESC 64

#define NM_BUF_SIZE "/sys/module/netmap/parameters/buf_size"

/** netmap runtime configuration options */
typedef struct {
	int nr_rx_slots;
	int nr_tx_slots;
} netmap_opt_t;

/** Ring for mapping pktin/pktout queues to netmap descriptors */
struct netmap_ring_t {
	unsigned int first; /**< Index of first netmap descriptor */
	unsigned int last;  /**< Index of last netmap descriptor */
	unsigned int num;   /**< Number of netmap descriptors */
	/** Netmap metadata for the device */
	struct nm_desc *desc[NM_MAX_DESC];
	unsigned int cur;	/**< Index of current netmap descriptor */
	odp_ticketlock_t lock;  /**< Queue lock */
};

typedef union ODP_ALIGNED_CACHE {
	struct netmap_ring_t s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct netmap_ring_t))];
} netmap_ring_t;

/** Netmap ring slot */
typedef struct  {
	char *buf;	/**< Slot buffer pointer */
	uint16_t len;	/**< Slot length */
} netmap_slot_t;

/** Packet socket using netmap mmaped rings for both Rx and Tx */
typedef struct {
	odp_pool_t pool;		/**< pool to alloc packets from */
	uint32_t if_flags;		/**< interface flags */
	uint32_t mtu;			/**< maximum transmission unit */
	int sockfd;			/**< control socket */
	unsigned char if_mac[ETH_ALEN]; /**< eth mac address */
	char nm_name[IF_NAMESIZE + 7];  /**< netmap:<ifname> */
	char if_name[IF_NAMESIZE];	/**< interface name used in ioctl */
	odp_bool_t is_virtual;		/**< nm virtual port (VALE/pipe) */
	uint32_t num_rx_rings;		/**< number of nm rx rings */
	uint32_t num_tx_rings;		/**< number of nm tx rings */
	unsigned int num_rx_desc_rings;	/**< number of rx descriptor rings */
	unsigned int num_tx_desc_rings;	/**< number of tx descriptor rings */
	odp_bool_t lockless_rx;		/**< no locking for rx */
	odp_bool_t lockless_tx;		/**< no locking for tx */
	/** mapping of pktin queues to netmap rx descriptors */
	netmap_ring_t rx_desc_ring[PKTIO_MAX_QUEUES];
	/** mapping of pktout queues to netmap tx descriptors */
	netmap_ring_t tx_desc_ring[PKTIO_MAX_QUEUES];
	netmap_opt_t opt;               /**< options */
} pkt_netmap_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_netmap_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_netmap_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_netmap_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

static int disable_pktio; /** !0 this pktio disabled, 0 enabled */
static int netmap_stats_reset(pktio_entry_t *pktio_entry);

static int read_netmap_buf_size(void)
{
	FILE  *file;
	char str[128];
	int size = 0;

	file = fopen(NM_BUF_SIZE, "rt");
	if (file == NULL) {
		/* File not found */
		return 0;
	}

	if (fgets(str, sizeof(str), file) != NULL) {
		/* Read netmap buffer size */
		if (sscanf(str, "%i", &size) != 1)
			size = 0;
	}

	fclose(file);

	return size;
}

static int lookup_opt(const char *opt_name, const char *drv_name, int *val)
{
	const char *base = "pktio_netmap";
	int ret;

	ret = _odp_libconfig_lookup_ext_int(base, drv_name, opt_name, val);
	if (ret == 0)
		ODP_ERR("Unable to find netmap configuration option: %s\n",
			opt_name);

	return ret;
}

static int init_options(pktio_entry_t *pktio_entry)
{
	netmap_opt_t *opt = &pkt_priv(pktio_entry)->opt;

	if (!lookup_opt("nr_rx_slots", "virt",
			&opt->nr_rx_slots))
		return -1;
	if (opt->nr_rx_slots < 0 ||
	    opt->nr_rx_slots > 4096) {
		ODP_ERR("Invalid number of RX slots\n");
		return -1;
	}

	if (!lookup_opt("nr_tx_slots", "virt",
			&opt->nr_tx_slots))
		return -1;
	if (opt->nr_tx_slots < 0 ||
	    opt->nr_tx_slots > 4096) {
		ODP_ERR("Invalid number of TX slots\n");
		return -1;
	}

	ODP_PRINT("netmap interface: %s\n",
		  pkt_priv(pktio_entry)->if_name);
	ODP_PRINT("  num_rx_desc: %d\n", opt->nr_rx_slots);
	ODP_PRINT("  num_tx_desc: %d\n", opt->nr_tx_slots);

	return 0;
}

static int netmap_do_ioctl(pktio_entry_t *pktio_entry, unsigned long cmd,
			   int subcmd)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	struct ethtool_value eval;
	struct ifreq ifr;
	int err;
	int fd = pkt_nm->sockfd;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",
		 pkt_priv(pktio_entry)->if_name);

	switch (cmd) {
	case SIOCSIFFLAGS:
		ifr.ifr_flags = pkt_nm->if_flags & 0xffff;
		break;
	case SIOCETHTOOL:
		eval.cmd = subcmd;
		eval.data = 0;
		ifr.ifr_data = (caddr_t)&eval;
		break;
	default:
		break;
	}
	err = ioctl(fd, cmd, &ifr);
	if (err)
		goto done;

	switch (cmd) {
	case SIOCGIFFLAGS:
		pkt_nm->if_flags = (ifr.ifr_flags << 16) |
			(0xffff & ifr.ifr_flags);
		break;
	case SIOCETHTOOL:
		if (subcmd == ETHTOOL_GLINK)
			return eval.data;
		break;
	default:
		break;
	}
done:
	if (err)
		ODP_ERR("ioctl err %d %lu: %s\n", err, cmd, strerror(errno));

	return err;
}

/**
 * Map netmap rings to pktin/pktout queues
 *
 * @param rings          Array of netmap descriptor rings
 * @param num_queues     Number of pktin/pktout queues
 * @param num_rings      Number of matching netmap rings
 */
static inline void map_netmap_rings(netmap_ring_t *rings,
				    unsigned num_queues, unsigned num_rings)
{
	struct netmap_ring_t *desc_ring;
	unsigned rings_per_queue;
	unsigned remainder;
	unsigned mapped_rings;
	unsigned i;
	unsigned desc_id = 0;

	rings_per_queue = num_rings / num_queues;
	remainder = num_rings % num_queues;

	if (remainder)
		ODP_DBG("WARNING: Netmap rings mapped unevenly to queues\n");

	for (i = 0; i < num_queues; i++) {
		desc_ring = &rings[i].s;
		if (i < remainder)
			mapped_rings = rings_per_queue + 1;
		else
			mapped_rings = rings_per_queue;

		desc_ring->first = desc_id;
		desc_ring->cur = desc_id;
		desc_ring->last = desc_ring->first + mapped_rings - 1;
		desc_ring->num = mapped_rings;

		desc_id = desc_ring->last + 1;
	}
}

static int netmap_input_queues_config(pktio_entry_t *pktio_entry,
				      const odp_pktin_queue_param_t *p)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;
	unsigned num_queues = p->num_queues;
	odp_bool_t lockless;

	/* Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED)
		lockless = 1;
	else
		lockless = (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE);

	if (p->hash_enable && num_queues > 1) {
		if (rss_conf_set_fd(pkt_priv(pktio_entry)->sockfd,
				    pkt_priv(pktio_entry)->if_name,
				    &p->hash_proto)) {
			ODP_ERR("Failed to configure input hash\n");
			return -1;
		}
	}

	pkt_nm->lockless_rx = lockless;

	return 0;
}

static int netmap_output_queues_config(pktio_entry_t *pktio_entry,
				       const odp_pktout_queue_param_t *p)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);

	pkt_nm->lockless_tx = (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE);

	return 0;
}

/**
 * Close netmap descriptors
 *
 * Can be reopened using netmap_start() function.
 *
 * @param pktio_entry    Packet IO entry
 */
static inline void netmap_close_descriptors(pktio_entry_t *pktio_entry)
{
	int i, j;
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		for (j = 0; j < NM_MAX_DESC; j++) {
			if (pkt_nm->rx_desc_ring[i].s.desc[j] != NULL) {
				nm_close(pkt_nm->rx_desc_ring[i].s.desc[j]);
				pkt_nm->rx_desc_ring[i].s.desc[j] = NULL;
			}
		}
		for (j = 0; j < NM_MAX_DESC; j++) {
			if (pkt_nm->tx_desc_ring[i].s.desc[j] != NULL) {
				nm_close(pkt_nm->tx_desc_ring[i].s.desc[j]);
				pkt_nm->tx_desc_ring[i].s.desc[j] = NULL;
			}
		}
	}

	pkt_nm->num_rx_desc_rings = 0;
	pkt_nm->num_tx_desc_rings = 0;
}

static int netmap_close(pktio_entry_t *pktio_entry)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);

	netmap_close_descriptors(pktio_entry);

	if (pkt_nm->sockfd != -1 && close(pkt_nm->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int netmap_link_status(pktio_entry_t *pktio_entry)
{
	if (pkt_priv(pktio_entry)->is_virtual)
		return 1;

	return link_status_fd(pkt_priv(pktio_entry)->sockfd,
			      pkt_priv(pktio_entry)->if_name);
}

/**
 * Wait for netmap link to come up
 *
 * @param pktio_entry    Packet IO entry
 *
 * @retval  1 link is up
 * @retval  0 link is down
 * @retval <0 on failure
 */
static inline int netmap_wait_for_link(pktio_entry_t *pktio_entry)
{
	int i;
	int ret;

	/* Wait for the link to come up */
	for (i = 0; i <= NM_WAIT_TIMEOUT; i++) {
		ret = netmap_link_status(pktio_entry);
		if (ret == -1)
			return -1;
		/* nm_open() causes the physical link to reset. When using a
		 * direct attached loopback cable there may be a small delay
		 * until the opposing end's interface comes back up again. In
		 * this case without the additional sleep pktio validation
		 * tests fail. */
		if (!pkt_priv(pktio_entry)->is_virtual)
			sleep(1);
		if (ret == 1)
			return 1;
	}
	ODP_DBG("%s link is down\n", pkt_priv(pktio_entry)->if_name);
	return 0;
}

/**
 * Initialize netmap capability values
 *
 * @param pktio_entry    Packet IO entry
 */
static void netmap_init_capability(pktio_entry_t *pktio_entry)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	odp_pktio_capability_t *capa = &pktio_entry->s.capa;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues = PKTIO_MAX_QUEUES;
	if (pkt_nm->num_rx_rings < PKTIO_MAX_QUEUES)
		capa->max_input_queues = pkt_nm->num_rx_rings;
	if (capa->max_input_queues > NM_MAX_DESC) {
		/* Have to use a single descriptor to fetch packets from all
		 * netmap rings */
		capa->max_input_queues = 1;
		ODP_DBG("Unable to store all %" PRIu32 " rx rings (max %d)\n"
			"  max input queues: %u\n", pkt_nm->num_rx_rings,
			NM_MAX_DESC, capa->max_input_queues);
	}

	capa->max_output_queues = PKTIO_MAX_QUEUES;
	if (pkt_nm->num_tx_rings < PKTIO_MAX_QUEUES)
		capa->max_output_queues = pkt_nm->num_tx_rings;
	if (capa->max_output_queues > NM_MAX_DESC) {
		capa->max_output_queues = NM_MAX_DESC;
		ODP_DBG("Unable to store all %" PRIu32 " tx rings (max %d)\n"
			"  max output queues: %u\n", pkt_nm->num_tx_rings,
			NM_MAX_DESC, capa->max_output_queues);
	}

	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
}

/**
 * Open a netmap interface
 *
 * In addition to standard interfaces (with or without modified netmap drivers)
 * virtual VALE and pipe interfaces are also supported. These can be used for
 * example for testing packet IO functionality without any physical interfaces.
 *
 * To use virtual interfaces the 'netdev' device name has to begin with 'vale'
 * prefix. A valid VALE device name would be e.g. 'vale0'. Pipe device names
 * have to include also '{NN' (master) or '}NN' (slave) suffix. A valid pipe
 * master would be e.g. 'vale0{0' and a slave to the same pipe 'vale0}0'.
 *
 * Netmap requires standard interface names to begin with 'netmap:' prefix.
 * netmap_open() adds the prefix if it is missing. Virtual interfaces don't
 * require the 'netmap:' prefix.
 *
 * @param id             Packet IO handle
 * @param pktio_entry    Packet IO entry
 * @param netdev         Packet IO device name
 * @param pool           Default pool from which to allocate storage for packets
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static int netmap_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		       const char *netdev, odp_pool_t pool)
{
	int i;
	int err;
	int sockfd;
	const char *prefix;
	uint32_t mtu;
	uint32_t nm_buf_size;
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	struct nm_desc *desc;
	odp_pktin_hash_proto_t hash_proto;
	odp_pktio_stats_t cur_stats;

	if (disable_pktio)
		return -1;

	if (pool == ODP_POOL_INVALID)
		return -1;

	/* Init pktio entry */
	memset(pkt_nm, 0, sizeof(*pkt_nm));
	pkt_nm->sockfd = -1;
	pkt_nm->pool = pool;

	/* allow interface to be opened with or without the 'netmap:' prefix */
	prefix = "netmap:";
	if (strncmp(netdev, "netmap:", 7) == 0)
		netdev += 7;
	if (strncmp(netdev, "vale", 4) == 0) {
		pkt_nm->is_virtual = 1;
		prefix = "";
	}

	snprintf(pkt_nm->nm_name, sizeof(pkt_nm->nm_name), "%s%s", prefix,
		 netdev);
	snprintf(pkt_nm->if_name, sizeof(pkt_nm->if_name), "%s", netdev);

	/* Initialize runtime options */
	if (init_options(pktio_entry)) {
		ODP_ERR("Initializing runtime options failed\n");
		return -1;
	}

	/* Read netmap buffer size */
	nm_buf_size = read_netmap_buf_size();
	if (!nm_buf_size) {
		ODP_ERR("Unable to read netmap buf size\n");
		return -1;
	}

	if (!pkt_nm->is_virtual) {
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sockfd == -1) {
			ODP_ERR("Cannot get device control socket\n");
			return -1;
		}
		pkt_nm->sockfd = sockfd;

		/* Use either interface MTU or netmap buffer size as MTU,
		 * whichever is smaller. */
		mtu = mtu_get_fd(pkt_nm->sockfd, pkt_nm->if_name);
		if (mtu == 0) {
			ODP_ERR("Unable to read interface MTU\n");
			goto error;
		}
		pkt_nm->mtu = (mtu < nm_buf_size) ? mtu : nm_buf_size;

		/* Netmap requires that interface MTU size <= nm buf size */
		if (mtu > nm_buf_size) {
			if (mtu_set_fd(pkt_nm->sockfd, pkt_nm->if_name,
				       nm_buf_size)) {
				ODP_ERR("Unable to set interface MTU\n");
				goto error;
			}
		}
	}
	/* Dummy open here to check if netmap module is available and to read
	 * capability info. */
	desc = nm_open(pkt_nm->nm_name, NULL, 0, NULL);
	if (desc == NULL) {
		ODP_ERR("nm_open(%s) failed\n", pkt_nm->nm_name);
		goto error;
	}
	pkt_nm->num_rx_rings = desc->nifp->ni_rx_rings;
	pkt_nm->num_tx_rings = desc->nifp->ni_tx_rings;

	netmap_init_capability(pktio_entry);

	nm_close(desc);

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_nm->rx_desc_ring[i].s.lock);
		odp_ticketlock_init(&pkt_nm->tx_desc_ring[i].s.lock);
	}

	if (pkt_nm->is_virtual) {
		static unsigned mac;
		uint32_t tid = syscall(SYS_gettid);

		if ((int)tid == -1)
			ODP_DBG("Unable to fetch thread ID. VALE port MAC "
				"addresses may not be unique.\n");

		pktio_entry->s.capa.max_input_queues = 1;
		pktio_entry->s.capa.set_op.op.promisc_mode = 0;
		pkt_nm->mtu = nm_buf_size;
		pktio_entry->s.stats_type = STATS_UNSUPPORTED;
		/* Set MAC address for virtual interface */
		pkt_nm->if_mac[0] = 0x2;
		pkt_nm->if_mac[1] = (tid >> 24) & 0xff;
		pkt_nm->if_mac[2] = (tid >> 16) & 0xff;
		pkt_nm->if_mac[3] = (tid >> 8) & 0xff;
		pkt_nm->if_mac[4] = tid & 0xff;
		pkt_nm->if_mac[5] = ++mac;

		return 0;
	}

	/* Check if RSS is supported. If not, set 'max_input_queues' to 1. */
	if (rss_conf_get_supported_fd(pkt_nm->sockfd, netdev,
				      &hash_proto) == 0) {
		ODP_DBG("RSS not supported\n");
		pktio_entry->s.capa.max_input_queues = 1;
	}

	err = netmap_do_ioctl(pktio_entry, SIOCGIFFLAGS, 0);
	if (err)
		goto error;
	if ((pkt_nm->if_flags & IFF_UP) == 0)
		ODP_DBG("%s is down\n", pkt_nm->if_name);

	err = mac_addr_get_fd(pkt_nm->sockfd, netdev, pkt_nm->if_mac);
	if (err)
		goto error;

	/* netmap uses only ethtool to get statistics counters */
	err = ethtool_stats_get_fd(pkt_nm->sockfd, pkt_nm->if_name, &cur_stats);
	if (err) {
		ODP_ERR("netmap pktio %s does not support statistics counters\n",
			pkt_nm->if_name);
		pktio_entry->s.stats_type = STATS_UNSUPPORTED;
	} else {
		pktio_entry->s.stats_type = STATS_ETHTOOL;
	}

	(void)netmap_stats_reset(pktio_entry);

	return 0;

error:
	netmap_close(pktio_entry);
	return -1;
}

static int netmap_start(pktio_entry_t *pktio_entry)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	netmap_ring_t *desc_ring;
	struct nm_desc *desc_ptr;
	unsigned i;
	unsigned j;
	unsigned num_rx_desc = 0;
	uint64_t flags;
	odp_pktin_mode_t in_mode = pktio_entry->s.param.in_mode;
	odp_pktout_mode_t out_mode = pktio_entry->s.param.out_mode;

	/* If no pktin/pktout queues have been configured. Configure one
	 * for each direction. */
	if (!pktio_entry->s.num_in_queue &&
	    in_mode != ODP_PKTIN_MODE_DISABLED) {
		odp_pktin_queue_param_t param;

		odp_pktin_queue_param_init(&param);
		param.num_queues = 1;
		if (odp_pktin_queue_config(pktio_entry->s.handle, &param))
			return -1;
	}
	if (!pktio_entry->s.num_out_queue &&
	    out_mode == ODP_PKTOUT_MODE_DIRECT) {
		odp_pktout_queue_param_t param;

		odp_pktout_queue_param_init(&param);
		param.num_queues = 1;
		if (odp_pktout_queue_config(pktio_entry->s.handle, &param))
			return -1;
	}

	if (pkt_nm->num_rx_desc_rings == pktio_entry->s.num_in_queue &&
	    pkt_nm->num_tx_desc_rings == pktio_entry->s.num_out_queue)
		return (netmap_wait_for_link(pktio_entry) == 1) ? 0 : -1;

	netmap_close_descriptors(pktio_entry);

	/* Map pktin/pktout queues to netmap rings */
	if (pktio_entry->s.num_in_queue) {
		/* In single queue case only one netmap descriptor is
		 * required. */
		num_rx_desc = (pktio_entry->s.num_in_queue == 1) ? 1 :
				pkt_nm->num_rx_rings;

		map_netmap_rings(pkt_nm->rx_desc_ring,
				 pktio_entry->s.num_in_queue, num_rx_desc);
	}
	if (pktio_entry->s.num_out_queue)
		/* Enough to map only one netmap tx ring per pktout queue */
		map_netmap_rings(pkt_nm->tx_desc_ring,
				 pktio_entry->s.num_out_queue,
				 pktio_entry->s.num_out_queue);

	/* Use nm_open() to parse netmap flags from interface name */
	desc_ptr = nm_open(pkt_nm->nm_name, NULL, 0, NULL);
	if (desc_ptr == NULL) {
		ODP_ERR("nm_start(%s) failed\n", pkt_nm->nm_name);
		goto error;
	}
	struct nm_desc base_desc = *desc_ptr;

	nm_close(desc_ptr);

	base_desc.self = &base_desc;
	base_desc.mem = NULL;
	if (pkt_priv(pktio_entry)->is_virtual) {
		base_desc.req.nr_rx_slots =
			pkt_priv(pktio_entry)->opt.nr_rx_slots;
		base_desc.req.nr_tx_slots =
			pkt_priv(pktio_entry)->opt.nr_tx_slots;
	}
	base_desc.req.nr_ringid = 0;
	if ((base_desc.req.nr_flags & NR_REG_MASK) == NR_REG_ALL_NIC ||
	    (base_desc.req.nr_flags & NR_REG_MASK) == NR_REG_ONE_NIC) {
		base_desc.req.nr_flags &= ~NR_REG_MASK;
		if (num_rx_desc == 1)
			base_desc.req.nr_flags |= NR_REG_ALL_NIC;
		else
			base_desc.req.nr_flags |= NR_REG_ONE_NIC;
	}

	/* Only the first rx descriptor does mmap */
	desc_ring = pkt_nm->rx_desc_ring;
	flags = NM_OPEN_IFNAME | NETMAP_NO_TX_POLL;
	if (pkt_priv(pktio_entry)->is_virtual)
		flags |= NM_OPEN_RING_CFG;
	desc_ring[0].s.desc[0] = nm_open(pkt_nm->nm_name, NULL, flags,
					 &base_desc);
	if (desc_ring[0].s.desc[0] == NULL) {
		ODP_ERR("nm_start(%s) failed\n", pkt_nm->nm_name);
		goto error;
	}
	/* Open rest of the rx descriptors (one per netmap ring) */
	flags = NM_OPEN_IFNAME | NETMAP_NO_TX_POLL | NM_OPEN_NO_MMAP;
	if (pkt_priv(pktio_entry)->is_virtual)
		flags |= NM_OPEN_RING_CFG;
	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
		for (j = desc_ring[i].s.first; j <= desc_ring[i].s.last; j++) {
			if (i == 0 && j == 0) { /* First already opened */
				if (num_rx_desc > 1)
					continue;
				else
					break;
			}
			base_desc.req.nr_ringid = j;
			desc_ring[i].s.desc[j] = nm_open(pkt_nm->nm_name, NULL,
							 flags, &base_desc);
			if (desc_ring[i].s.desc[j] == NULL) {
				ODP_ERR("nm_start(%s) failed\n",
					pkt_nm->nm_name);
				goto error;
			}
		}
	}
	/* Open tx descriptors */
	desc_ring = pkt_nm->tx_desc_ring;
	flags = NM_OPEN_IFNAME | NM_OPEN_NO_MMAP;
	if (pkt_priv(pktio_entry)->is_virtual)
		flags |= NM_OPEN_RING_CFG;

	if ((base_desc.req.nr_flags & NR_REG_MASK) == NR_REG_ALL_NIC) {
		base_desc.req.nr_flags &= ~NR_REG_ALL_NIC;
		base_desc.req.nr_flags |= NR_REG_ONE_NIC;
	}

	for (i = 0; i < pktio_entry->s.num_out_queue; i++) {
		for (j = desc_ring[i].s.first; j <= desc_ring[i].s.last; j++) {
			base_desc.req.nr_ringid = j;
			desc_ring[i].s.desc[j] = nm_open(pkt_nm->nm_name, NULL,
							 flags, &base_desc);
			if (desc_ring[i].s.desc[j] == NULL) {
				ODP_ERR("nm_start(%s) failed\n",
					pkt_nm->nm_name);
				goto error;
			}
		}
	}
	pkt_nm->num_rx_desc_rings = pktio_entry->s.num_in_queue;
	pkt_nm->num_tx_desc_rings = pktio_entry->s.num_out_queue;
	/* Wait for the link to come up */
	return (netmap_wait_for_link(pktio_entry) == 1) ? 0 : -1;

error:
	netmap_close_descriptors(pktio_entry);
	return -1;
}

static int netmap_stop(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

/**
 * Create ODP packets from netmap packets
 *
 * @param pktio_entry    Packet IO entry
 * @param pkt_tbl        Array for new ODP packet handles
 * @param slot_tbl       Array of netmap ring slots
 * @param slot_num       Number of netmap ring slots
 * @param ts             Pointer to pktin timestamp
 *
 * @retval Number of created packets
 */
static inline int netmap_pkt_to_odp(pktio_entry_t *pktio_entry,
				    odp_packet_t pkt_tbl[],
				    netmap_slot_t slot_tbl[], int16_t slot_num,
				    odp_time_t *ts)
{
	odp_packet_t pkt;
	odp_pool_t pool = pkt_priv(pktio_entry)->pool;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_hdr_t parsed_hdr;
	int i;
	int num;
	int alloc_len;

	/* Allocate maximum sized packets */
	alloc_len = pkt_priv(pktio_entry)->mtu;

	num = packet_alloc_multi(pool, alloc_len, pkt_tbl, slot_num);

	for (i = 0; i < num; i++) {
		netmap_slot_t slot;
		uint16_t len;

		slot = slot_tbl[i];
		len = slot.len;

		odp_prefetch(slot.buf);

		if (pktio_cls_enabled(pktio_entry)) {
			if (cls_classify_packet(pktio_entry,
						(const uint8_t *)slot.buf, len,
						len, &pool, &parsed_hdr, true))
				goto fail;
		}

		pkt = pkt_tbl[i];
		pkt_hdr = packet_hdr(pkt);
		pull_tail(pkt_hdr, alloc_len - len);

		/* For now copy the data in the mbuf,
		   worry about zero-copy later */
		if (odp_packet_copy_from_mem(pkt, 0, len, slot.buf) != 0)
			goto fail;

		pkt_hdr->input = pktio_entry->s.handle;

		if (pktio_cls_enabled(pktio_entry))
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
		else
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer,
					   pktio_entry->s.in_chksums);

		packet_set_ts(pkt_hdr, ts);
	}

	return i;

fail:
	odp_packet_free_multi(&pkt_tbl[i], num - i);
	return i;
}

static inline int netmap_recv_desc(pktio_entry_t *pktio_entry,
				   struct nm_desc *desc,
				   odp_packet_t pkt_table[], int num)
{
	struct netmap_ring *ring;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	netmap_slot_t slot_tbl[num];
	char *buf;
	uint32_t slot_id;
	uint32_t mtu = pkt_priv(pktio_entry)->mtu;
	int i;
	int ring_id = desc->cur_rx_ring;
	int num_rx = 0;
	int num_rings = desc->last_rx_ring - desc->first_rx_ring + 1;

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp)
		ts = &ts_val;

	for (i = 0; i < num_rings && num_rx != num; i++) {
		if (ring_id > desc->last_rx_ring)
			ring_id = desc->first_rx_ring;

		ring = NETMAP_RXRING(desc->nifp, ring_id);

		while (!nm_ring_empty(ring) && num_rx != num) {
			slot_id = ring->cur;
			buf = NETMAP_BUF(ring, ring->slot[slot_id].buf_idx);

			if (odp_likely(ring->slot[slot_id].len <= mtu)) {
				slot_tbl[num_rx].buf = buf;
				slot_tbl[num_rx].len = ring->slot[slot_id].len;
				num_rx++;
			} else {
				ODP_DBG("Dropped oversized packet: %" PRIu16 " "
					"B\n", ring->slot[slot_id].len);
			}
			ring->cur = nm_ring_next(ring, slot_id);
			ring->head = ring->cur;
		}
		ring_id++;
	}
	desc->cur_rx_ring = ring_id;

	if (num_rx) {
		if (ts != NULL)
			ts_val = odp_time_global();
		return netmap_pkt_to_odp(pktio_entry, pkt_table, slot_tbl,
					 num_rx, ts);
	}
	return 0;
}

static int netmap_fd_set(pktio_entry_t *pktio_entry, int index, fd_set *readfds)
{
	struct nm_desc *desc;
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	unsigned first_desc_id = pkt_nm->rx_desc_ring[index].s.first;
	unsigned last_desc_id = pkt_nm->rx_desc_ring[index].s.last;
	unsigned desc_id;
	int num_desc = pkt_nm->rx_desc_ring[index].s.num;
	int i;
	int max_fd = 0;

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

	if (!pkt_nm->lockless_rx)
		odp_ticketlock_lock(&pkt_nm->rx_desc_ring[index].s.lock);

	desc_id = pkt_nm->rx_desc_ring[index].s.cur;

	for (i = 0; i < num_desc; i++) {
		if (desc_id > last_desc_id)
			desc_id = first_desc_id;

		desc = pkt_nm->rx_desc_ring[index].s.desc[desc_id];

		FD_SET(desc->fd, readfds);
		if (desc->fd > max_fd)
			max_fd = desc->fd;
		desc_id++;
	}
	pkt_nm->rx_desc_ring[index].s.cur = desc_id;

	if (!pkt_nm->lockless_rx)
		odp_ticketlock_unlock(&pkt_nm->rx_desc_ring[index].s.lock);

	return max_fd;
}

static int netmap_recv(pktio_entry_t *pktio_entry, int index,
		       odp_packet_t pkt_table[], int num)
{
	struct nm_desc *desc;
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	unsigned first_desc_id = pkt_nm->rx_desc_ring[index].s.first;
	unsigned last_desc_id = pkt_nm->rx_desc_ring[index].s.last;
	unsigned desc_id;
	int num_desc = pkt_nm->rx_desc_ring[index].s.num;
	int i;
	int num_rx = 0;
	int max_fd = 0;
	fd_set empty_rings;

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

	FD_ZERO(&empty_rings);

	if (!pkt_nm->lockless_rx)
		odp_ticketlock_lock(&pkt_nm->rx_desc_ring[index].s.lock);

	desc_id = pkt_nm->rx_desc_ring[index].s.cur;

	for (i = 0; i < num_desc && num_rx != num; i++) {
		if (desc_id > last_desc_id)
			desc_id = first_desc_id;

		desc = pkt_nm->rx_desc_ring[index].s.desc[desc_id];

		num_rx += netmap_recv_desc(pktio_entry, desc,
					   &pkt_table[num_rx], num - num_rx);

		if (num_rx != num) {
			FD_SET(desc->fd, &empty_rings);
			if (desc->fd > max_fd)
				max_fd = desc->fd;
		}
		desc_id++;
	}
	pkt_nm->rx_desc_ring[index].s.cur = desc_id;

	if (num_rx != num) {
		struct timeval tout = {.tv_sec = 0, .tv_usec = 0};

		if (select(max_fd + 1, &empty_rings, NULL, NULL, &tout) == -1)
			ODP_ERR("RX: select error\n");
	}
	if (!pkt_nm->lockless_rx)
		odp_ticketlock_unlock(&pkt_nm->rx_desc_ring[index].s.lock);

	return num_rx;
}

static int netmap_recv_tmo(pktio_entry_t *pktio_entry, int index,
			   odp_packet_t pkt_table[], int num, uint64_t usecs)
{
	struct timeval timeout;
	int ret;
	int maxfd;
	fd_set readfds;

	ret = netmap_recv(pktio_entry, index, pkt_table, num);
	if (ret != 0)
		return ret;

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);
	FD_ZERO(&readfds);
	maxfd = netmap_fd_set(pktio_entry, index, &readfds);

	if (select(maxfd + 1, &readfds, NULL, NULL, &timeout) == 0)
		return 0;

	return netmap_recv(pktio_entry, index, pkt_table, num);
}

static int netmap_recv_mq_tmo(pktio_entry_t *pktio_entry[], int index[],
			      int num_q, odp_packet_t pkt_table[], int num,
			      unsigned *from, uint64_t usecs)
{
	struct timeval timeout;
	int i;
	int ret;
	int maxfd = -1, maxfd2;
	fd_set readfds;

	for (i = 0; i < num_q; i++) {
		ret = netmap_recv(pktio_entry[i], index[i], pkt_table, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	FD_ZERO(&readfds);

	for (i = 0; i < num_q; i++) {
		maxfd2 = netmap_fd_set(pktio_entry[i], index[i], &readfds);
		if (maxfd2 > maxfd)
			maxfd = maxfd2;
	}

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	if (select(maxfd + 1, &readfds, NULL, NULL, &timeout) == 0)
		return 0;

	for (i = 0; i < num_q; i++) {
		ret = netmap_recv(pktio_entry[i], index[i], pkt_table, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	return 0;
}

static int netmap_send(pktio_entry_t *pktio_entry, int index,
		       const odp_packet_t pkt_table[], int num)
{
	pkt_netmap_t *pkt_nm = pkt_priv(pktio_entry);
	struct pollfd polld;
	struct nm_desc *desc;
	struct netmap_ring *ring;
	int i;
	int nb_tx;
	int desc_id;
	odp_packet_t pkt;
	uint32_t pkt_len;
	unsigned slot_id;
	char *buf;

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

	/* Only one netmap tx ring per pktout queue */
	desc_id = pkt_nm->tx_desc_ring[index].s.cur;
	desc = pkt_nm->tx_desc_ring[index].s.desc[desc_id];
	ring = NETMAP_TXRING(desc->nifp, desc->cur_tx_ring);

	if (!pkt_nm->lockless_tx)
		odp_ticketlock_lock(&pkt_nm->tx_desc_ring[index].s.lock);

	polld.fd = desc->fd;
	polld.events = POLLOUT;

	for (nb_tx = 0; nb_tx < num; nb_tx++) {
		pkt = pkt_table[nb_tx];
		pkt_len = odp_packet_len(pkt);

		if (pkt_len > pkt_nm->mtu) {
			if (nb_tx == 0)
				__odp_errno = EMSGSIZE;
			break;
		}
		for (i = 0; i < NM_INJECT_RETRIES; i++) {
			if (nm_ring_empty(ring)) {
				poll(&polld, 1, 0);
				continue;
			}
			slot_id = ring->cur;
			ring->slot[slot_id].flags = 0;
			ring->slot[slot_id].len = pkt_len;

			buf = NETMAP_BUF(ring, ring->slot[slot_id].buf_idx);

			if (odp_packet_copy_to_mem(pkt, 0, pkt_len, buf)) {
				i = NM_INJECT_RETRIES;
				break;
			}
			ring->cur = nm_ring_next(ring, slot_id);
			ring->head = ring->cur;
			break;
		}
		if (i == NM_INJECT_RETRIES)
			break;
	}
	/* Send pending packets */
	poll(&polld, 1, 0);

	if (!pkt_nm->lockless_tx)
		odp_ticketlock_unlock(&pkt_nm->tx_desc_ring[index].s.lock);

	if (odp_unlikely(nb_tx == 0)) {
		if (__odp_errno != 0)
			return -1;
	} else {
		odp_packet_free_multi(pkt_table, nb_tx);
	}

	return nb_tx;
}

static int netmap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pkt_priv(pktio_entry)->if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static uint32_t netmap_mtu_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->mtu;
}

static int netmap_promisc_mode_set(pktio_entry_t *pktio_entry,
				   odp_bool_t enable)
{
	if (pkt_priv(pktio_entry)->is_virtual) {
		__odp_errno = ENOTSUP;
		return -1;
	}

	return promisc_mode_set_fd(pkt_priv(pktio_entry)->sockfd,
				   pkt_priv(pktio_entry)->if_name, enable);
}

static int netmap_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	if (pkt_priv(pktio_entry)->is_virtual)
		return 0;

	return promisc_mode_get_fd(pkt_priv(pktio_entry)->sockfd,
				   pkt_priv(pktio_entry)->if_name);
}

static int netmap_capability(pktio_entry_t *pktio_entry,
			     odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.capa;
	return 0;
}

static int netmap_stats(pktio_entry_t *pktio_entry,
			odp_pktio_stats_t *stats)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	return sock_stats_fd(pktio_entry,
			     stats,
			     pkt_priv(pktio_entry)->sockfd);
}

static int netmap_stats_reset(pktio_entry_t *pktio_entry)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->s.stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	return sock_stats_reset_fd(pktio_entry,
				   pkt_priv(pktio_entry)->sockfd);
}

static void netmap_print(pktio_entry_t *pktio_entry)
{
	odp_pktin_hash_proto_t hash_proto;

	if (rss_conf_get_fd(pkt_priv(pktio_entry)->sockfd,
			    pkt_priv(pktio_entry)->if_name, &hash_proto))
		rss_conf_print(&hash_proto);
}

static int netmap_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_NETMAP")) {
		ODP_PRINT("PKTIO: netmap pktio skipped,"
			  " enabled export ODP_PKTIO_DISABLE_NETMAP=1.\n");
		disable_pktio = 1;
	} else  {
		ODP_PRINT("PKTIO: initialized netmap pktio,"
			  " use export ODP_PKTIO_DISABLE_NETMAP=1 to disable.\n"
			  " Netmap prefixes are netmap:eth0 or vale:eth0. Refer to"
			  " Netmap documentation for usage information.\n");
	}
	return 0;
}

const pktio_if_ops_t netmap_pktio_ops = {
	.name = "netmap",
	.print = netmap_print,
	.init_global = netmap_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = netmap_open,
	.close = netmap_close,
	.start = netmap_start,
	.stop = netmap_stop,
	.link_status = netmap_link_status,
	.stats = netmap_stats,
	.stats_reset = netmap_stats_reset,
	.mtu_get = netmap_mtu_get,
	.promisc_mode_set = netmap_promisc_mode_set,
	.promisc_mode_get = netmap_promisc_mode_get,
	.mac_get = netmap_mac_addr_get,
	.mac_set = NULL,
	.capability = netmap_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = netmap_input_queues_config,
	.output_queues_config = netmap_output_queues_config,
	.recv = netmap_recv,
	.recv_tmo = netmap_recv_tmo,
	.recv_mq_tmo = netmap_recv_mq_tmo,
	.send = netmap_send,
	.fd_set = netmap_fd_set
};

#endif /* _ODP_PKTIO_NETMAP */
