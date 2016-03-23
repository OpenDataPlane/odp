/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifdef ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <unistd.h>

#include <odp/api/cpumask.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>

#include <odp/helper/eth.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

/* Has dpdk_pktio_init() been called */
static odp_bool_t dpdk_initialized;

#define PMD_EXT(drv) \
extern void devinitfn_##drv(void)

PMD_EXT(cryptodev_aesni_mb_pmd_drv);
PMD_EXT(pmd_qat_drv);
PMD_EXT(pmd_af_packet_drv);
PMD_EXT(rte_bnx2x_driver);
PMD_EXT(rte_bnx2xvf_driver);
PMD_EXT(bond_drv);
PMD_EXT(rte_cxgbe_driver);
PMD_EXT(em_pmd_drv);
PMD_EXT(pmd_igb_drv);
PMD_EXT(pmd_igbvf_drv);
PMD_EXT(rte_enic_driver);
PMD_EXT(rte_fm10k_driver);
PMD_EXT(rte_i40e_driver);
PMD_EXT(rte_i40evf_driver);
PMD_EXT(rte_ixgbe_driver);
PMD_EXT(rte_ixgbevf_driver);
PMD_EXT(rte_mlx4_driver);
PMD_EXT(rte_mlx5_driver);
PMD_EXT(pmd_mpipe_xgbe_drv);
PMD_EXT(pmd_mpipe_gbe_drv);
PMD_EXT(rte_nfp_net_driver);
PMD_EXT(pmd_null_drv);
PMD_EXT(pmd_pcap_drv);
PMD_EXT(pmd_ring_drv);
PMD_EXT(pmd_szedata2_drv);
PMD_EXT(rte_virtio_driver);
PMD_EXT(rte_vmxnet3_driver);
PMD_EXT(pmd_xenvirt_drv);

/*
 * This function is not called from anywhere, it's only purpose is to make sure
 * that if ODP and DPDK are statically linked to an application, the GCC
 * constuctors of the PMDs are linked as well. Otherwise the linker would omit
 * them. It's not an issue with dynamic linking. */
void refer_constructors(void);
void refer_constructors(void)
{
#ifdef RTE_LIBRTE_PMD_AESNI_MB
	devinitfn_cryptodev_aesni_mb_pmd_drv();
#endif
#ifdef RTE_LIBRTE_PMD_QAT
	devinitfn_pmd_qat_drv();
#endif
#ifdef RTE_LIBRTE_PMD_AF_PACKET
	devinitfn_pmd_af_packet_drv();
#endif
#ifdef RTE_LIBRTE_BNX2X_PMD
	devinitfn_rte_bnx2x_driver();
	devinitfn_rte_bnx2xvf_driver();
#endif
#ifdef RTE_LIBRTE_PMD_BOND
	devinitfn_bond_drv();
#endif
#ifdef RTE_LIBRTE_CXGBE_PMD
	devinitfn_rte_cxgbe_driver();
#endif
#ifdef RTE_LIBRTE_EM_PMD
	devinitfn_em_pmd_drv();
#endif
#ifdef RTE_LIBRTE_IGB_PMD
	devinitfn_pmd_igb_drv();
	devinitfn_pmd_igbvf_drv();
#endif
#ifdef RTE_LIBRTE_ENIC_PMD
	devinitfn_rte_enic_driver();
#endif
#ifdef RTE_LIBRTE_FM10K_PMD
	devinitfn_rte_fm10k_driver();
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	devinitfn_rte_i40e_driver();
	devinitfn_rte_i40evf_driver();
#endif
#ifdef RTE_LIBRTE_IXGBE_PMD
	devinitfn_rte_ixgbe_driver();
	devinitfn_rte_ixgbevf_driver();
#endif
#ifdef RTE_LIBRTE_MLX4_PMD
	devinitfn_rte_mlx4_driver();
#endif
#ifdef RTE_LIBRTE_MLX5_PMD
	devinitfn_rte_mlx5_driver();
#endif
#ifdef RTE_LIBRTE_MPIPE_PMD
	devinitfn_pmd_mpipe_xgbe_drv()
	devinitfn_pmd_mpipe_gbe_drv()
#endif
#ifdef RTE_LIBRTE_NFP_PMD
	devinitfn_rte_nfp_net_driver();
#endif
#ifdef RTE_LIBRTE_PMD_NULL
	devinitfn_pmd_null_drv();
#endif
#ifdef RTE_LIBRTE_PMD_PCAP
	devinitfn_pmd_pcap_drv();
#endif
#ifdef RTE_LIBRTE_PMD_RING
	devinitfn_pmd_ring_drv();
#endif
#ifdef RTE_LIBRTE_PMD_SZEDATA2
	devinitfn_pmd_szedata2_drv();
#endif
#ifdef RTE_LIBRTE_VIRTIO_PMD
	devinitfn_rte_virtio_driver();
#endif
#ifdef RTE_LIBRTE_VMXNET3_PMD
	devinitfn_rte_vmxnet3_driver();
#endif
#ifdef RTE_LIBRTE_PMD_XENVIRT
	devinitfn_pmd_xenvirt_drv();
#endif
}

/* Test if s has only digits or not. Dpdk pktio uses only digits.*/
static int dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

static uint32_t dpdk_vdev_mtu_get(uint8_t port_id)
{
	struct rte_eth_dev_info dev_info = {0};
	struct ifreq ifr;
	int sockfd;
	uint32_t mtu;

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ODP_ERR("Failed to create control socket\n");
		return 0;
	}

	mtu = mtu_get_fd(sockfd, ifr.ifr_name);
	close(sockfd);
	return mtu;
}

static uint32_t dpdk_mtu_get(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint32_t mtu;

	if (rte_eth_dev_get_mtu(pkt_dpdk->port_id, (uint16_t *)&mtu))
		return 0;

	/* Some DPDK PMD virtual devices do not support getting MTU size.
	 * Try to use system call if DPDK cannot get MTU value.
	 */
	if (mtu == 0)
		mtu = dpdk_vdev_mtu_get(pkt_dpdk->port_id);

	/* Mbuf chaining not yet supported */
	if (pkt_dpdk->data_room && pkt_dpdk->data_room < mtu)
		return pkt_dpdk->data_room;

	return mtu;
}

static void rss_conf_to_hash_proto(struct rte_eth_rss_conf *rss_conf,
				   const odp_pktin_hash_proto_t *hash_proto)
{
	memset(rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	if (hash_proto->proto.ipv4_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_UDP;
	if (hash_proto->proto.ipv4_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_TCP;
	if (hash_proto->proto.ipv4)
		rss_conf->rss_hf |= ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
				    ETH_RSS_NONFRAG_IPV4_OTHER;
	if (hash_proto->proto.ipv6_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_UDP |
				    ETH_RSS_IPV6_UDP_EX;
	if (hash_proto->proto.ipv6_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_TCP |
				    ETH_RSS_IPV6_TCP_EX;
	if (hash_proto->proto.ipv6)
		rss_conf->rss_hf |= ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
				    ETH_RSS_NONFRAG_IPV6_OTHER |
				    ETH_RSS_IPV6_EX;
	rss_conf->rss_key = NULL;
}

static int dpdk_setup_port(pktio_entry_t *pktio_entry)
{
	int ret;
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	struct rte_eth_rss_conf rss_conf;

	rss_conf_to_hash_proto(&rss_conf, &pkt_dpdk->hash);

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.max_rx_pkt_len = pkt_dpdk->data_room,
			.split_hdr_size = 0,
			.header_split   = 0,
			.hw_ip_checksum = 0,
			.hw_vlan_filter = 0,
			.jumbo_frame    = 1,
			.hw_strip_crc   = 0,
		},
		.rx_adv_conf = {
			.rss_conf = rss_conf,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	ret = rte_eth_dev_configure(pkt_dpdk->port_id,
				    pktio_entry->s.num_in_queue,
				    pktio_entry->s.num_out_queue, &port_conf);
	if (ret < 0) {
		ODP_ERR("Failed to setup device: err=%d, port=%" PRIu8 "\n",
			ret, pkt_dpdk->port_id);
		return -1;
	}
	return 0;
}

static int dpdk_close(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	unsigned idx;
	unsigned i, j;

	/* Free cache packets */
	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		idx = pkt_dpdk->rx_cache[i].s.idx;

		for (j = 0; j < pkt_dpdk->rx_cache[i].s.count; j++)
			rte_pktmbuf_free(pkt_dpdk->rx_cache[i].s.pkt[idx++]);
	}

	if (pkt_dpdk->started)
		rte_eth_dev_close(pkt_dpdk->port_id);

	return 0;
}

static int dpdk_pktio_init(void)
{
	int dpdk_argc;
	int i;
	odp_cpumask_t mask;
	char mask_str[ODP_CPUMASK_STR_SIZE];
	int32_t masklen;
	int mem_str_len;
	int cmd_len;
	cpu_set_t original_cpuset;
	struct rte_config *cfg;

	/**
	 * DPDK init changes the affinity of the calling thread, so after it
	 * returns the original affinity is restored. Only the first active
	 * core is passed to rte_eal_init(), as the rest would be used for
	 * DPDK's special lcore threads, which are only available through
	 * rte_eal_[mp_]remote_launch(), but not through ODP API's.
	 * Nevertheless, odp_local_init() makes sure for the rest of
	 * the DPDK libraries ODP threads look like proper DPDK threads.
	 */
	CPU_ZERO(&original_cpuset);
	i = pthread_getaffinity_np(pthread_self(),
				   sizeof(original_cpuset), &original_cpuset);
	if (i != 0) {
		ODP_ERR("Failed to read thread affinity: %d\n", i);
		return -1;
	}

	odp_cpumask_zero(&mask);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &original_cpuset)) {
			odp_cpumask_set(&mask, i);
			break;
		}
	}
	masklen = odp_cpumask_to_str(&mask, mask_str, ODP_CPUMASK_STR_SIZE);

	if (masklen < 0) {
		ODP_ERR("CPU mask error: d\n", masklen);
		return -1;
	}

	mem_str_len = snprintf(NULL, 0, "%d", DPDK_MEMORY_MB);

	/* masklen includes the terminating null as well */
	cmd_len = strlen("odpdpdk -c -m ") + masklen + mem_str_len +
			strlen(" ");

	char full_cmd[cmd_len];

	/* first argument is facility log, simply bind it to odpdpdk for now.*/
	cmd_len = snprintf(full_cmd, cmd_len, "odpdpdk -c %s -m %d",
			   mask_str, DPDK_MEMORY_MB);

	for (i = 0, dpdk_argc = 1; i < cmd_len; ++i) {
		if (isspace(full_cmd[i]))
			++dpdk_argc;
	}

	char *dpdk_argv[dpdk_argc];

	dpdk_argc = rte_strsplit(full_cmd, strlen(full_cmd), dpdk_argv,
				 dpdk_argc, ' ');
	for (i = 0; i < dpdk_argc; ++i)
		ODP_DBG("arg[%d]: %s\n", i, dpdk_argv[i]);

	i = rte_eal_init(dpdk_argc, dpdk_argv);

	if (i < 0) {
		ODP_ERR("Cannot init the Intel DPDK EAL!\n");
		return -1;
	} else if (i + 1 != dpdk_argc) {
		ODP_DBG("Some DPDK args were not processed!\n");
		ODP_DBG("Passed: %d Consumed %d\n", dpdk_argc, i + 1);
	}
	ODP_DBG("rte_eal_init OK\n");

	rte_set_log_level(RTE_LOG_WARNING);

	i = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
				   &original_cpuset);
	if (i)
		ODP_ERR("Failed to reset thread affinity: %d\n", i);

	cfg = rte_eal_get_configuration();
	for (i = 0; i < RTE_MAX_LCORE; i++)
		cfg->lcore_role[i] = ROLE_RTE;

	return 0;
}

/* Placeholder for DPDK global init */
static int odp_dpdk_pktio_init_global(void)
{
	return 0;
}

static int odp_dpdk_pktio_init_local(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		ODP_ERR("getcpu failed\n");
		return -1;
	}

	RTE_PER_LCORE(_lcore_id) = cpu;

	return 0;
}

static int dpdk_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;
	odp_bool_t lockless;

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	if (p->hash_enable && p->num_queues > 1)
		pktio_entry->s.pkt_dpdk.hash = p->hash_proto;

	pktio_entry->s.pkt_dpdk.lockless_rx = lockless;

	return 0;
}

static int dpdk_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	odp_bool_t lockless;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_dpdk->lockless_tx = lockless;

	return 0;
}

static int dpdk_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *netdev,
		     odp_pool_t pool)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	struct rte_eth_dev_info dev_info;
	struct rte_mempool *pkt_pool;
	odp_pool_info_t pool_info;
	uint16_t data_room;
	uint32_t mtu;
	int i;

	if (getenv("ODP_PKTIO_DISABLE_DPDK"))
		return -1;

	if (pool == ODP_POOL_INVALID)
		return -1;

	if (!dpdk_netdev_is_valid(netdev)) {
		ODP_ERR("Invalid dpdk netdev: %s\n", netdev);
		return -1;
	}

	/* Initialize DPDK here instead of odp_init_global() to enable running
	 * 'make check' without root privileges */
	if (dpdk_initialized == 0) {
		dpdk_pktio_init();
		dpdk_initialized = 1;
	}

	/* Init pktio entry */
	memset(pkt_dpdk, 0, sizeof(*pkt_dpdk));

	pkt_dpdk->pool = pool;
	pkt_dpdk->port_id = atoi(netdev);

	snprintf(pkt_dpdk->pool_name, sizeof(pkt_dpdk->pool_name), "pktpool_%s",
		 netdev);

	if (rte_eth_dev_count() == 0) {
		ODP_ERR("No DPDK ports found\n");
		return -1;
	}

	if (odp_pool_info(pool, &pool_info) < 0) {
		ODP_ERR("Failed to read pool info\n");
		return -1;
	}

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
	rte_eth_dev_info_get(pkt_dpdk->port_id, &dev_info);
	pkt_dpdk->capa.max_input_queues = RTE_MIN(dev_info.max_rx_queues,
						  PKTIO_MAX_QUEUES);
	pkt_dpdk->capa.max_output_queues = RTE_MIN(dev_info.max_tx_queues,
						   PKTIO_MAX_QUEUES);
	pkt_dpdk->capa.set_op.op.promisc_mode = 1;

	mtu = dpdk_mtu_get(pktio_entry);
	if (mtu == 0) {
		ODP_ERR("Failed to read interface MTU\n");
		return -1;
	}
	pkt_dpdk->mtu = mtu + ODPH_ETHHDR_LEN;

	if (!strcmp(dev_info.driver_name, "rte_ixgbe_pmd"))
		pkt_dpdk->min_rx_burst = DPDK_IXGBE_MIN_RX_BURST;
	else
		pkt_dpdk->min_rx_burst = 0;

	/* Look for previously opened packet pool */
	pkt_pool = rte_mempool_lookup(pkt_dpdk->pool_name);
	if (pkt_pool == NULL)
		pkt_pool = rte_pktmbuf_pool_create(pkt_dpdk->pool_name,
						   DPDK_NB_MBUF,
						   DPDK_MEMPOOL_CACHE_SIZE, 0,
						   DPDK_MBUF_BUF_SIZE,
						   rte_socket_id());
	if (pkt_pool == NULL) {
		ODP_ERR("Cannot init mbuf packet pool\n");
		return -1;
	}
	pkt_dpdk->pkt_pool = pkt_pool;

	data_room = rte_pktmbuf_data_room_size(pkt_dpdk->pkt_pool) -
			RTE_PKTMBUF_HEADROOM;
	pkt_dpdk->data_room = RTE_MIN(pool_info.params.pkt.len, data_room);

	/* Mbuf chaining not yet supported */
	 pkt_dpdk->mtu = RTE_MIN(pkt_dpdk->mtu, pkt_dpdk->data_room);

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_dpdk->rx_lock[i]);
		odp_ticketlock_init(&pkt_dpdk->tx_lock[i]);
	}

	return 0;
}

static int dpdk_start(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t port_id = pkt_dpdk->port_id;
	int ret;
	unsigned i;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	/* init port */
	if (dpdk_setup_port(pktio_entry)) {
		ODP_ERR("Failed to configure device\n");
		return -1;
	}
	/* Init TX queues */
	for (i = 0; i < pktio_entry->s.num_out_queue; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, DPDK_NM_TX_DESC,
					     rte_eth_dev_socket_id(port_id),
					     NULL);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}
	/* Init RX queues */
	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, DPDK_NM_RX_DESC,
					     rte_eth_dev_socket_id(port_id),
					     NULL, pkt_dpdk->pkt_pool);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}
	/* Start device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		ODP_ERR("Device start failed: err=%d, port=%" PRIu8 "\n",
			ret, port_id);
		return -1;
	}
	pkt_dpdk->started = 1;

	return 0;
}

static int dpdk_stop(pktio_entry_t *pktio_entry)
{
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.port_id);

	return 0;
}

static inline int mbuf_to_pkt(pktio_entry_t *pktio_entry,
			      odp_packet_t pkt_table[],
			      struct rte_mbuf *mbuf_table[],
			      uint16_t num)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint16_t pkt_len;
	struct rte_mbuf *mbuf;
	void *buf;
	int i, j;
	int nb_pkts = 0;

	for (i = 0; i < num; i++) {
		mbuf = mbuf_table[i];
		if (odp_unlikely(mbuf->nb_segs != 1)) {
			ODP_ERR("Segmented buffers not supported\n");
			goto fail;
		}

		buf = rte_pktmbuf_mtod(mbuf, char *);
		odp_prefetch(buf);

		pkt_len = rte_pktmbuf_pkt_len(mbuf);

		if (pktio_cls_enabled(pktio_entry)) {
			if (_odp_packet_cls_enq(pktio_entry,
						(const uint8_t *)buf, pkt_len,
						&pkt_table[nb_pkts]))
				nb_pkts++;
		} else {
			pkt = packet_alloc(pktio_entry->s.pkt_dpdk.pool,
					   pkt_len, 1);
			if (pkt == ODP_PACKET_INVALID) {
				ODP_ERR("packet_alloc failed\n");
				goto fail;
			}

			pkt_hdr = odp_packet_hdr(pkt);

			/* For now copy the data in the mbuf,
			   worry about zero-copy later */
			if (odp_packet_copydata_in(pkt, 0, pkt_len, buf) != 0) {
				ODP_ERR("odp_packet_copydata_in failed\n");
				odp_packet_free(pkt);
				goto fail;
			}

			packet_parse_l2(pkt_hdr);

			pkt_hdr->input = pktio_entry->s.handle;

			if (mbuf->ol_flags & PKT_RX_RSS_HASH) {
				pkt_hdr->has_hash = 1;
				pkt_hdr->flow_hash = mbuf->hash.rss;
			}

			pkt_table[nb_pkts++] = pkt;
		}
		rte_pktmbuf_free(mbuf);
	}

	return nb_pkts;

fail:
	ODP_ERR("Creating ODP packet failed\n");
	for (j = i; j < num; j++)
		rte_pktmbuf_free(mbuf_table[j]);

	return (i > 0 ? i : -1);
}

static inline int pkt_to_mbuf(pktio_entry_t *pktio_entry,
			      struct rte_mbuf *mbuf_table[],
			      odp_packet_t pkt_table[], uint16_t num)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	int i;
	char *data;
	uint16_t pkt_len;

	for (i = 0; i < num; i++) {
		pkt_len = odp_packet_len(pkt_table[i]);

		if (pkt_len > pkt_dpdk->mtu) {
			if (i == 0)
				__odp_errno = EMSGSIZE;
			break;
		}

		mbuf_table[i] = rte_pktmbuf_alloc(pkt_dpdk->pkt_pool);
		if (mbuf_table[i] == NULL) {
			ODP_ERR("Failed to alloc mbuf\n");
			break;
		}

		rte_pktmbuf_reset(mbuf_table[i]);

		data = rte_pktmbuf_append(mbuf_table[i], pkt_len);

		if (data == NULL) {
			ODP_ERR("Failed to append mbuf\n");
			rte_pktmbuf_free(mbuf_table[i]);
			break;
		}

		odp_packet_copydata_out(pkt_table[i], 0, pkt_len, data);
	}
	return i;
}

static int dpdk_recv_queue(pktio_entry_t *pktio_entry,
			   int index,
			   odp_packet_t pkt_table[],
			   int num)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	pkt_cache_t *rx_cache = &pkt_dpdk->rx_cache[index];
	int nb_rx;
	struct rte_mbuf *rx_mbufs[num];
	int i;
	unsigned cache_idx;

	if (odp_unlikely(pktio_entry->s.state == STATE_STOP))
		return 0;

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_lock(&pkt_dpdk->rx_lock[index]);
	/**
	 * ixgbe_pmd has a minimum supported RX burst size ('min_rx_burst'). If
	 * 'num' < 'min_rx_burst', 'min_rx_burst' is used as rte_eth_rx_burst()
	 * argument and the possibly received extra packets are cached for the
	 * next dpdk_recv_queue() call to use.
	 *
	 * Either use cached packets or receive new ones. Not both during the
	 * same call. */
	if (rx_cache->s.count > 0) {
		for (i = 0; i < num && rx_cache->s.count; i++) {
			rx_mbufs[i] = rx_cache->s.pkt[rx_cache->s.idx];
			rx_cache->s.idx++;
			rx_cache->s.count--;
		}
		nb_rx = i;
	} else if ((unsigned)num < pkt_dpdk->min_rx_burst) {
		struct rte_mbuf *new_mbufs[pkt_dpdk->min_rx_burst];

		nb_rx = rte_eth_rx_burst(pktio_entry->s.pkt_dpdk.port_id, index,
					 new_mbufs, pkt_dpdk->min_rx_burst);

		rx_cache->s.idx = 0;
		for (i = 0; i < nb_rx; i++) {
			if (i < num) {
				rx_mbufs[i] = new_mbufs[i];
			} else {
				cache_idx = rx_cache->s.count;
				rx_cache->s.pkt[cache_idx] = new_mbufs[i];
				rx_cache->s.count++;
			}
		}
		nb_rx = RTE_MIN(num, nb_rx);

	} else {
		nb_rx = rte_eth_rx_burst(pktio_entry->s.pkt_dpdk.port_id, index,
					 rx_mbufs, num);
	}

	if (nb_rx > 0)
		nb_rx = mbuf_to_pkt(pktio_entry, pkt_table, rx_mbufs, nb_rx);

	if (!pktio_entry->s.pkt_dpdk.lockless_rx)
		odp_ticketlock_unlock(&pkt_dpdk->rx_lock[index]);

	return nb_rx;
}

static int dpdk_send_queue(pktio_entry_t *pktio_entry,
			   int index,
			   odp_packet_t pkt_table[],
			   int num)
{
	struct rte_mbuf *tx_mbufs[num];
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	int tx_pkts;
	int i;
	int mbufs;

	if (odp_unlikely(pktio_entry->s.state == STATE_STOP))
		return 0;

	if (!pktio_entry->s.pkt_dpdk.lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

	mbufs = pkt_to_mbuf(pktio_entry, tx_mbufs, pkt_table, num);

	tx_pkts = rte_eth_tx_burst(pkt_dpdk->port_id, index,
				   tx_mbufs, mbufs);

	if (odp_unlikely(tx_pkts < num)) {
		for (i = tx_pkts; i < mbufs; i++)
			rte_pktmbuf_free(tx_mbufs[i]);
	}

	odp_packet_free_multi(pkt_table, tx_pkts);

	if (!pktio_entry->s.pkt_dpdk.lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (odp_unlikely(tx_pkts == 0 && __odp_errno != 0))
		return -1;

	return tx_pkts;
}

static int dpdk_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	rte_eth_macaddr_get(pktio_entry->s.pkt_dpdk.port_id,
			    (struct ether_addr *)mac_addr);
	return ETH_ALEN;
}

static int dpdk_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable)
{
	if (enable)
		rte_eth_promiscuous_enable(pktio_entry->s.pkt_dpdk.port_id);
	else
		rte_eth_promiscuous_disable(pktio_entry->s.pkt_dpdk.port_id);
	return 0;
}

static int dpdk_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return rte_eth_promiscuous_get(pktio_entry->s.pkt_dpdk.port_id);
}

static int dpdk_capability(pktio_entry_t *pktio_entry,
			   odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.pkt_dpdk.capa;
	return 0;
}

static int dpdk_link_status(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(struct rte_eth_link));

	rte_eth_link_get_nowait(pktio_entry->s.pkt_dpdk.port_id, &link);

	return link.link_status;
}

const pktio_if_ops_t dpdk_pktio_ops = {
	.name = "dpdk",
	.init_global = odp_dpdk_pktio_init_global,
	.init_local = odp_dpdk_pktio_init_local,
	.term = NULL,
	.open = dpdk_open,
	.close = dpdk_close,
	.start = dpdk_start,
	.stop = dpdk_stop,
	.recv_queue = dpdk_recv_queue,
	.send_queue = dpdk_send_queue,
	.link_status = dpdk_link_status,
	.mtu_get = dpdk_mtu_get,
	.promisc_mode_set = dpdk_promisc_mode_set,
	.promisc_mode_get = dpdk_promisc_mode_get,
	.mac_get = dpdk_mac_addr_get,
	.capability = dpdk_capability,
	.input_queues_config = dpdk_input_queues_config,
	.output_queues_config = dpdk_output_queues_config
};

#endif /* ODP_PKTIO_DPDK */
