/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#if defined(_ODP_MDEV) && _ODP_MDEV == 1

#include <linux/types.h>
#include <protocols/eth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <odp_packet_io_internal.h>
#include <odp_posix_extensions.h>

#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/drv/hints.h>
#include <odp/drv/mmio.h>

#include <pktio/common.h>
#include <pktio/ethtool.h>
#include <pktio/mdev.h>
#include <pktio/sysfs.h>
#include <pktio/uapi_net_mdev.h>

#define MODULE_NAME "i40e"

#define I40E_TX_BUF_SIZE 2048U
#define I40E_RX_BUF_SIZE 2048U

#define I40E_TX_PACKET_LEN_MIN 17

/* RX queue definitions */
#define I40E_RX_QUEUE_NUM_MAX 32

/** RX descriptor */
typedef struct {
	odp_u64le_t addr;
#define I40E_RXD_QW1_LEN_S 38
#define I40E_RXD_QW1_LEN_M (0x3FFFULL << I40E_RXD_QW1_LEN_S)
	odp_u64le_t status_error_len;
	odp_u64le_t reserved[2];
} i40e_rx_desc_t;

/** RX queue data */
typedef struct ODP_ALIGNED_CACHE {
	i40e_rx_desc_t *rx_descs;	/**< RX queue base */
	odp_u32le_t *doorbell;		/**< RX queue doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */
	uint16_t cidx;			/**< Next RX desc to handle */

	mdev_dma_area_t rx_data;	/**< RX packet payload area */

	odp_ticketlock_t lock;		/**< RX queue lock */
} i40e_rx_queue_t;

/* TX queue definitions */
#define I40E_TX_QUEUE_NUM_MAX 32

typedef struct {
	odp_u64le_t addr;

#define I40E_TXD_DTYPE_DATA	0UL

#define I40E_TXD_CMD_EOP	0x0001UL
#define I40E_TXD_CMD_RS		0x0002UL
#define I40E_TXD_CMD_ICRC	0x0004UL

#define I40E_TXD_QW1_CMD_S	4
#define I40E_TXD_QW1_L2TAG1_S	48
#define I40E_TXD_QW1_OFFSET_S	16
#define I40E_TXD_QW1_LEN_S	34
	odp_u64le_t cmd_type_offset_len;
} i40e_tx_desc_t;

/** TX queue data */
typedef struct ODP_ALIGNED_CACHE {
	i40e_tx_desc_t *tx_descs;	/**< TX queue base */
	odp_u32le_t *doorbell;		/**< TX queue doorbell */

	uint16_t tx_queue_len;		/**< Number of TX desc entries */
	uint16_t pidx;			/**< Next TX desc to insert */

	odp_u32le_t *cidx;		/**< Last TX desc processed by HW */

	mdev_dma_area_t tx_data;	/**< TX packet payload area */

	odp_ticketlock_t lock;		/**< TX queue lock */
} i40e_tx_queue_t;

/** Packet socket using mediated i40e device */
typedef struct {
	/** RX queue hot data */
	i40e_rx_queue_t rx_queues[I40E_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	i40e_tx_queue_t tx_queues[I40E_TX_QUEUE_NUM_MAX];

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	int sockfd;			/**< control socket */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_i40e_data_t;

static void i40e_rx_refill(i40e_rx_queue_t *rxq, uint16_t from, uint16_t num);
static void i40e_wait_link_up(pktio_entry_t *pktio_entry);
static int i40e_close(pktio_entry_t *pktio_entry);

static int i40e_mmio_register(pktio_ops_i40e_data_t *pkt_i40e,
			      uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_i40e->mmio == NULL);

	pkt_i40e->mmio = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (pkt_i40e->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int i40e_rx_queue_register(pktio_ops_i40e_data_t *pkt_i40e,
				  uint64_t offset, uint64_t size)
{
	uint16_t rxq_idx = pkt_i40e->capa.max_input_queues++;
	i40e_rx_queue_t *rxq = &pkt_i40e->rx_queues[rxq_idx];
	uint64_t doorbell_offset;
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(rxq_idx < ARRAY_SIZE(pkt_i40e->rx_queues));

	odp_ticketlock_init(&rxq->lock);

	ret = ethtool_ringparam_get_fd(pkt_i40e->sockfd,
				       pkt_i40e->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	rxq->rx_queue_len = ering.rx_pending;

	ret = sysfs_attr_u64_get(&doorbell_offset,
				 "/sys/class/net/%s"
				 "/queues/rx-%u/i40e/doorbell_offset",
				 pkt_i40e->mdev.if_name, rxq_idx);
	if (ret) {
		ODP_ERR("Cannot get %s rx-%u doorbell_offset\n",
			pkt_i40e->mdev.if_name, rxq_idx);
		return -1;
	}

	rxq->doorbell =
	    (odp_u32le_t *)(void *)(pkt_i40e->mmio + doorbell_offset);

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) <= size);

	rxq->rx_descs = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	rxq->rx_data.size = rxq->rx_queue_len * I40E_RX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_i40e->mdev, &rxq->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	/* Need 1 desc gap to keep tail from touching head */
	i40e_rx_refill(rxq, 0, rxq->rx_queue_len - 1);

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", rxq->rx_queue_len);

	return 0;
}

static int i40e_tx_queue_register(pktio_ops_i40e_data_t *pkt_i40e,
				  uint64_t offset, uint64_t size)
{
	uint16_t txq_idx = pkt_i40e->capa.max_output_queues++;
	i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[txq_idx];
	uint64_t doorbell_offset;
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(txq_idx < ARRAY_SIZE(pkt_i40e->tx_queues));

	odp_ticketlock_init(&txq->lock);

	ret = ethtool_ringparam_get_fd(pkt_i40e->sockfd,
				       pkt_i40e->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	txq->tx_queue_len = ering.tx_pending;

	ret = sysfs_attr_u64_get(&doorbell_offset,
				 "/sys/class/net/%s"
				 "/queues/tx-%u/i40e/doorbell_offset",
				 pkt_i40e->mdev.if_name, txq_idx);
	if (ret) {
		ODP_ERR("Cannot get %s tx-%u doorbell_offset\n",
			pkt_i40e->mdev.if_name, txq_idx);
		return -1;
	}

	txq->doorbell =
	    (odp_u32le_t *)(void *)(pkt_i40e->mmio + doorbell_offset);

	ODP_ASSERT(txq->tx_queue_len * sizeof(*txq->tx_descs) +
		   sizeof(*txq->cidx) <= size);

	txq->tx_descs = mdev_region_mmap(&pkt_i40e->mdev, offset, size);
	if (txq->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	txq->cidx = (odp_u32le_t *)(txq->tx_descs + txq->tx_queue_len);

	txq->tx_data.size = txq->tx_queue_len * I40E_TX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_i40e->mdev, &txq->tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", txq->tx_queue_len);

	return 0;
}

static int i40e_region_info_cb(mdev_device_t *mdev,
			       struct vfio_region_info *region_info)
{
	pktio_ops_i40e_data_t *pkt_i40e =
	    odp_container_of(mdev, pktio_ops_i40e_data_t, mdev);
	mdev_region_class_t class_info;

	if (vfio_get_region_cap_type(region_info, &class_info) < 0) {
		ODP_ERR("Cannot find class_info in region %u\n",
			region_info->index);
		return -1;
	}

	switch (class_info.type) {
	case VFIO_NET_MDEV_MMIO:
		return i40e_mmio_register(pkt_i40e,
					  region_info->offset,
					  region_info->size);

	case VFIO_NET_MDEV_RX_RING:
		return i40e_rx_queue_register(pkt_i40e,
					      region_info->offset,
					      region_info->size);

	case VFIO_NET_MDEV_TX_RING:
		return i40e_tx_queue_register(pkt_i40e,
					      region_info->offset,
					      region_info->size);

	default:
		ODP_ERR("Unexpected region %u (class %u:%u)\n",
			region_info->index, class_info.type,
			class_info.subtype);
		return -1;
	}
}

static int i40e_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *resource, odp_pool_t pool)
{
	pktio_ops_i40e_data_t *pkt_i40e;
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	pkt_i40e = ODP_OPS_DATA_ALLOC(sizeof(*pkt_i40e));
	if (odp_unlikely(pkt_i40e == NULL)) {
		ODP_ERR("Failed to allocate pktio_ops_i40e_data_t struct");
		return -1;
	}
	pktio_entry->s.ops_data = pkt_i40e;

	memset(pkt_i40e, 0, sizeof(*pkt_i40e));

	pkt_i40e->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (pkt_i40e->sockfd == -1) {
		ODP_ERR("Cannot get device control socket\n");
		goto out;
	}

	ret =
	    mdev_device_create(&pkt_i40e->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       i40e_region_info_cb);
	if (ret)
		goto out;

	pkt_i40e->pool = pool;

	i40e_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_i40e->mdev.if_name);

	return 0;

out:
	i40e_close(pktio_entry);
	return -1;
}

static int i40e_close(pktio_entry_t *pktio_entry)
{
	uint16_t i;

	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_i40e->mdev.if_name);

	mdev_device_destroy(&pkt_i40e->mdev);

	for (i = 0; i < pkt_i40e->capa.max_input_queues; i++) {
		i40e_rx_queue_t *rxq = &pkt_i40e->rx_queues[i];

		if (rxq->rx_data.size)
			mdev_dma_area_free(&pkt_i40e->mdev, &rxq->rx_data);
	}

	for (i = 0; i < pkt_i40e->capa.max_output_queues; i++) {
		i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[i];

		if (txq->tx_data.size)
			mdev_dma_area_free(&pkt_i40e->mdev, &txq->tx_data);
	}

	if (pkt_i40e->sockfd != -1)
		close(pkt_i40e->sockfd);

	ODP_OPS_DATA_FREE(pkt_i40e);

	return 0;
}

static void i40e_rx_refill(i40e_rx_queue_t *rxq, uint16_t from, uint16_t num)
{
	uint16_t i = from;

	while (num) {
		uint64_t iova = rxq->rx_data.iova + i * I40E_RX_BUF_SIZE;
		i40e_rx_desc_t *rxd = &rxq->rx_descs[i];

		rxd->addr = odp_cpu_to_le_64(iova);
		rxd->status_error_len = odp_cpu_to_le_64(0);

		i++;
		if (i >= rxq->rx_queue_len)
			i = 0;

		num--;
	}

	/* Ring the doorbell */
	odpdrv_mmio_u32le_write(i, rxq->doorbell);
}

static int i40e_recv(pktio_entry_t *pktio_entry, int rxq_idx,
		     odp_packet_t pkt_table[], int num)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;
	i40e_rx_queue_t *rxq = &pkt_i40e->rx_queues[rxq_idx];
	uint16_t refill_from;
	int rx_pkts = 0;

	if (!pkt_i40e->lockless_rx)
		odp_ticketlock_lock(&rxq->lock);

	/* Keep track of the start point to refill RX queue */
	refill_from = rxq->cidx ? rxq->cidx - 1 : rxq->rx_queue_len - 1;

	while (rx_pkts < num) {
		volatile i40e_rx_desc_t *rxd = &rxq->rx_descs[rxq->cidx];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt;
		uint16_t pkt_len;
		uint64_t status_error_len;
		int ret;

		status_error_len = odp_le_to_cpu_64(rxd->status_error_len);
		if (!status_error_len)
			break;

		pkt_len = (status_error_len & I40E_RXD_QW1_LEN_M) >>
		    I40E_RXD_QW1_LEN_S;

		pkt = odp_packet_alloc(pkt_i40e->pool, pkt_len);
		if (odp_unlikely(pkt == ODP_PACKET_INVALID))
			break;

		pkt_hdr = odp_packet_hdr(pkt);

		ret = odp_packet_copy_from_mem(pkt, 0, pkt_len,
					       (uint8_t *)rxq->rx_data.vaddr +
					       rxq->cidx * I40E_RX_BUF_SIZE);
		if (odp_unlikely(ret)) {
			odp_packet_free(pkt);
			break;
		}

		pkt_hdr->input = pktio_entry->s.handle;

		rxq->cidx++;
		if (odp_unlikely(rxq->cidx >= rxq->rx_queue_len))
			rxq->cidx = 0;

		pkt_table[rx_pkts] = pkt;
		rx_pkts++;
	}

	if (rx_pkts)
		i40e_rx_refill(rxq, refill_from, rx_pkts);

	if (!pkt_i40e->lockless_rx)
		odp_ticketlock_unlock(&rxq->lock);

	return rx_pkts;
}

/**
 * Helper function to build descriptor 2nd quad-word.
 */
static inline uint64_t txd_ctol(uint32_t cmd, uint32_t tag, uint32_t offset,
				uint32_t len)
{
	return I40E_TXD_DTYPE_DATA |
	    ((uint64_t)cmd << I40E_TXD_QW1_CMD_S) |
	    ((uint64_t)tag << I40E_TXD_QW1_L2TAG1_S) |
	    ((uint64_t)offset << I40E_TXD_QW1_OFFSET_S) |
	    ((uint64_t)len << I40E_TXD_QW1_LEN_S);
}

static int i40e_send(pktio_entry_t *pktio_entry, int txq_idx,
		     const odp_packet_t pkt_table[], int num)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;
	i40e_tx_queue_t *txq = &pkt_i40e->tx_queues[txq_idx];
	uint16_t budget, tx_txds = 0;
	int tx_pkts = 0;

	if (!pkt_i40e->lockless_tx)
		odp_ticketlock_lock(&txq->lock);

	/* Determine how many packets will fit in TX queue */
	budget = txq->tx_queue_len - 1;
	budget -= txq->pidx;
	budget += odp_le_to_cpu_32(*txq->cidx);
	budget &= txq->tx_queue_len - 1;

	while (tx_txds < budget && tx_pkts < num) {
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = txq->pidx * I40E_TX_BUF_SIZE;

		i40e_tx_desc_t *txd = &txq->tx_descs[txq->pidx];

		uint32_t txd_cmd = I40E_TXD_CMD_ICRC | I40E_TXD_CMD_EOP;

		/* Skip undersized packets silently */
		if (odp_unlikely(pkt_len < I40E_TX_PACKET_LEN_MIN)) {
			tx_pkts++;
			continue;
		}

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > I40E_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		/* Request CIDX update from firmware from time to time */
		if (!(txq->pidx & ((txq->tx_queue_len >> 2) - 1)))
			txd_cmd |= I40E_TXD_CMD_RS;

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       (uint8_t *)txq->tx_data.vaddr + offset);

		txd->addr = odp_cpu_to_le_64(txq->tx_data.iova + offset);
		txd->cmd_type_offset_len =
		    odp_cpu_to_le_64(txd_ctol(txd_cmd, 0, 0, pkt_len));

		txq->pidx++;
		if (odp_unlikely(txq->pidx >= txq->tx_queue_len))
			txq->pidx -= txq->tx_queue_len;

		tx_txds++;
		tx_pkts++;
	}

	/* Ring the doorbell */
	if (tx_pkts)
		odpdrv_mmio_u32le_write(txq->pidx, txq->doorbell);

	if (!pkt_i40e->lockless_tx)
		odp_ticketlock_unlock(&txq->lock);

	odp_packet_free_multi(pkt_table, tx_pkts);

	return tx_pkts;
}

static int i40e_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	return link_status_fd(pkt_i40e->sockfd, pkt_i40e->mdev.if_name);
}

static void i40e_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!i40e_link_status(pktio_entry))
		sleep(1);
}

static int i40e_capability(pktio_entry_t *pktio_entry,
			   odp_pktio_capability_t *capa)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	*capa = pkt_i40e->capa;
	return 0;
}

static int i40e_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_i40e->lockless_rx = 1;
	else
		pkt_i40e->lockless_rx = 0;

	return 0;
}

static int i40e_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_i40e->lockless_tx = 1;
	else
		pkt_i40e->lockless_tx = 0;

	return 0;
}

static int i40e_mac_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	pktio_ops_i40e_data_t *pkt_i40e = pktio_entry->s.ops_data;

	if (mac_addr_get_fd(pkt_i40e->sockfd, pkt_i40e->mdev.if_name,
			    mac_addr) < 0)
		return -1;

	return ETH_ALEN;
}

static int i40e_init_global(void)
{
	ODP_PRINT("PKTIO: initialized " MODULE_NAME " interface\n");
	return 0;
}

static pktio_ops_module_t i40e_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
		 .init_global = i40e_init_global,
	},

	.open = i40e_open,
	.close = i40e_close,

	.recv = i40e_recv,
	.send = i40e_send,

	.link_status = i40e_link_status,

	.capability = i40e_capability,

	.mac_get = i40e_mac_get,

	.input_queues_config = i40e_input_queues_config,
	.output_queues_config = i40e_output_queues_config,
};

/** i40e module entry point */
ODP_MODULE_CONSTRUCTOR(netmap_pktio_ops)
{
	odp_module_constructor(&i40e_pktio_ops);

	odp_subsystem_register_module(pktio_ops, &i40e_pktio_ops);
}

/*
 * Temporary variable to enable link this module,
 * will remove in Makefile scheme changes.
 */
int enable_link_i40e_pktio_ops;

#endif /* _ODP_MDEV */
