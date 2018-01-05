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

#define MODULE_NAME "e1000e"

#define E1000E_TX_BUF_SIZE 2048U
#define E1000E_RX_BUF_SIZE 2048U

/* RX queue definitions */
#define E1000E_RX_QUEUE_NUM_MAX 1

#define E1000_RDH_OFFSET 0x02810UL
#define E1000_RDT_OFFSET 0x02818UL

/** RX descriptor */
typedef struct {
	odp_u64le_t addr;
#define E1000E_RXD_STATUS_DONE        0x00000001UL
#define E1000E_RXD_STATUS_ERR_MASK    0xff000000UL
	odp_u32le_t status;
	odp_u16le_t length;
	odp_u16le_t vlan;
} e1000e_rx_desc_t;

/** RX queue data */
typedef struct ODP_ALIGNED_CACHE {
	e1000e_rx_desc_t *rx_descs;	/**< RX queue base */
	odp_u32le_t *doorbell;		/**< RX queue doorbell */

	uint16_t rx_queue_len;		/**< Number of RX desc entries */

	uint16_t cidx;			/**< Next RX desc to read */
	odp_u32le_t *pidx;		/**< Next RX desc HW is going to write */

	mdev_dma_area_t rx_data;	/**< RX packet payload area */

	odp_ticketlock_t lock;		/**< RX queue lock */
} e1000e_rx_queue_t;

/* TX queue definitions */
#define E1000E_TX_QUEUE_NUM_MAX 1

#define E1000_TDH_OFFSET 0x03810UL
#define E1000_TDT_OFFSET 0x03818UL

typedef struct {
	odp_u64le_t addr;			/* Address of data buffer */
#define E1000_TXD_CMD_EOP       0x01000000	/* End of Packet */
#define E1000_TXD_CMD_IFCS      0x02000000	/* Insert FCS (Ethernet CRC) */
	odp_u32le_t cmd;
	odp_u32le_t reserved;
} e1000e_tx_desc_t;

/** TX queue data */
typedef struct ODP_ALIGNED_CACHE {
	e1000e_tx_desc_t *tx_descs;	/**< TX queue base */
	odp_u32le_t *doorbell;		/**< TX queue doorbell */

	uint16_t tx_queue_len;		/**< Number of TX desc entries */

	uint16_t pidx;			/**< Next TX desc to write */
	odp_u32le_t *cidx;		/**< Next TX desc HW is going to read */

	mdev_dma_area_t tx_data;	/**< TX packet payload area */

	odp_ticketlock_t lock;		/**< TX queue lock */
} e1000e_tx_queue_t;

/** Packet socket using mediated e1000e device */
typedef struct {
	/** RX queue hot data */
	e1000e_rx_queue_t rx_queues[E1000E_RX_QUEUE_NUM_MAX];

	/** TX queue hot data */
	e1000e_tx_queue_t tx_queues[E1000E_TX_QUEUE_NUM_MAX];

	odp_pool_t pool;		/**< pool to alloc packets from */

	odp_bool_t lockless_rx;		/**< no locking for RX */
	odp_bool_t lockless_tx;		/**< no locking for TX */

	odp_pktio_capability_t capa;	/**< interface capabilities */

	uint8_t *mmio;			/**< MMIO region */

	int sockfd;			/**< control socket */

	mdev_device_t mdev;		/**< Common mdev data */
} pktio_ops_e1000e_data_t;

static void e1000e_rx_refill(e1000e_rx_queue_t *rxq, uint16_t from,
			     uint16_t num);
static void e1000e_wait_link_up(pktio_entry_t *pktio_entry);
static int e1000e_close(pktio_entry_t *pktio_entry);

static int e1000e_mmio_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				uint64_t offset, uint64_t size)
{
	ODP_ASSERT(pkt_e1000e->mmio == NULL);

	pkt_e1000e->mmio = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (pkt_e1000e->mmio == MAP_FAILED) {
		ODP_ERR("Cannot mmap MMIO\n");
		return -1;
	}

	ODP_DBG("Register MMIO region: 0x%llx@%016llx\n", size, offset);

	return 0;
}

static int e1000e_rx_queue_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				    uint64_t offset, uint64_t size)
{
	uint16_t rxq_idx = pkt_e1000e->capa.max_input_queues++;
	e1000e_rx_queue_t *rxq = &pkt_e1000e->rx_queues[rxq_idx];
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(rxq_idx < ARRAY_SIZE(pkt_e1000e->rx_queues));

	odp_ticketlock_init(&rxq->lock);

	ret = ethtool_ringparam_get_fd(pkt_e1000e->sockfd,
				       pkt_e1000e->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	rxq->rx_queue_len = ering.rx_pending;

	rxq->doorbell =
	    (odp_u32le_t *)(void *)(pkt_e1000e->mmio + E1000_RDT_OFFSET);

	ODP_ASSERT(rxq->rx_queue_len * sizeof(*rxq->rx_descs) <= size);

	rxq->rx_descs = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (rxq->rx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap RX queue\n");
		return -1;
	}

	rxq->pidx =
	    (odp_u32le_t *)(void *)(pkt_e1000e->mmio + E1000_RDH_OFFSET);

	rxq->rx_data.size = rxq->rx_queue_len * E1000E_RX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_e1000e->mdev, &rxq->rx_data);
	if (ret) {
		ODP_ERR("Cannot allocate RX queue DMA area\n");
		return -1;
	}

	/* Need 1 desc gap to keep tail from touching head */
	e1000e_rx_refill(rxq, 0, rxq->rx_queue_len - 1);

	ODP_DBG("Register RX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    RX descriptors: %u\n", rxq->rx_queue_len);

	return 0;
}

static int e1000e_tx_queue_register(pktio_ops_e1000e_data_t *pkt_e1000e,
				    uint64_t offset, uint64_t size)
{
	uint16_t txq_idx = pkt_e1000e->capa.max_output_queues++;
	e1000e_tx_queue_t *txq = &pkt_e1000e->tx_queues[txq_idx];
	struct ethtool_ringparam ering;
	int ret;

	ODP_ASSERT(txq_idx < ARRAY_SIZE(pkt_e1000e->tx_queues));

	odp_ticketlock_init(&txq->lock);

	ret = ethtool_ringparam_get_fd(pkt_e1000e->sockfd,
				       pkt_e1000e->mdev.if_name, &ering);
	if (ret) {
		ODP_ERR("Cannot get queue length\n");
		return -1;
	}
	txq->tx_queue_len = ering.tx_pending;

	txq->doorbell =
	    (odp_u32le_t *)(void *)(pkt_e1000e->mmio + E1000_TDT_OFFSET);

	ODP_ASSERT(txq->tx_queue_len * sizeof(*txq->tx_descs) <= size);

	txq->tx_descs = mdev_region_mmap(&pkt_e1000e->mdev, offset, size);
	if (txq->tx_descs == MAP_FAILED) {
		ODP_ERR("Cannot mmap TX queue\n");
		return -1;
	}

	txq->cidx =
	    (odp_u32le_t *)(void *)(pkt_e1000e->mmio + E1000_TDH_OFFSET);

	txq->tx_data.size = txq->tx_queue_len * E1000E_TX_BUF_SIZE;
	ret = mdev_dma_area_alloc(&pkt_e1000e->mdev, &txq->tx_data);
	if (ret) {
		ODP_ERR("Cannot allocate TX queue DMA area\n");
		return -1;
	}

	ODP_DBG("Register TX queue region: 0x%llx@%016llx\n", size, offset);
	ODP_DBG("    TX descriptors: %u\n", txq->tx_queue_len);

	return 0;
}

static int e1000e_region_info_cb(mdev_device_t *mdev,
				 struct vfio_region_info *region_info)
{
	pktio_ops_e1000e_data_t *pkt_e1000e =
	    odp_container_of(mdev, pktio_ops_e1000e_data_t, mdev);
	mdev_region_class_t class_info;

	if (vfio_get_region_cap_type(region_info, &class_info) < 0) {
		ODP_ERR("Cannot find class_info in region %u\n",
			region_info->index);
		return -1;
	}

	switch (class_info.type) {
	case VFIO_NET_MDEV_MMIO:
		return e1000e_mmio_register(pkt_e1000e,
					   region_info->offset,
					   region_info->size);

	case VFIO_NET_MDEV_RX_RING:
		return e1000e_rx_queue_register(pkt_e1000e,
					       region_info->offset,
					       region_info->size);

	case VFIO_NET_MDEV_TX_RING:
		return e1000e_tx_queue_register(pkt_e1000e,
					       region_info->offset,
					       region_info->size);

	default:
		ODP_ERR("Unexpected region %u (class %u:%u)\n",
			region_info->index, class_info.type,
			class_info.subtype);
		return -1;
	}
}

static int e1000e_open(odp_pktio_t id ODP_UNUSED,
		       pktio_entry_t *pktio_entry,
		       const char *resource, odp_pool_t pool)
{
	pktio_ops_e1000e_data_t *pkt_e1000e;
	int ret;

	ODP_ASSERT(pool != ODP_POOL_INVALID);

	if (strncmp(resource, NET_MDEV_PREFIX, strlen(NET_MDEV_PREFIX)))
		return -1;

	ODP_DBG("%s: probing resource %s\n", MODULE_NAME, resource);

	pkt_e1000e = ODP_OPS_DATA_ALLOC(sizeof(*pkt_e1000e));
	if (odp_unlikely(pkt_e1000e == NULL)) {
		ODP_ERR("Failed to allocate pktio_ops_e1000e_data_t struct");
		return -1;
	}
	pktio_entry->s.ops_data = pkt_e1000e;

	memset(pkt_e1000e, 0, sizeof(*pkt_e1000e));

	pkt_e1000e->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (pkt_e1000e->sockfd == -1) {
		ODP_ERR("Cannot get device control socket\n");
		goto out;
	}

	ret =
	    mdev_device_create(&pkt_e1000e->mdev, MODULE_NAME,
			       resource + strlen(NET_MDEV_PREFIX),
			       e1000e_region_info_cb);
	if (ret)
		goto out;

	pkt_e1000e->pool = pool;

	e1000e_wait_link_up(pktio_entry);

	ODP_DBG("%s: open %s is successful\n", MODULE_NAME,
		pkt_e1000e->mdev.if_name);

	return 0;

out:
	e1000e_close(pktio_entry);
	return -1;
}

static int e1000e_close(pktio_entry_t *pktio_entry)
{
	uint16_t i;

	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	ODP_DBG("%s: close %s\n", MODULE_NAME, pkt_e1000e->mdev.if_name);

	mdev_device_destroy(&pkt_e1000e->mdev);

	for (i = 0; i < pkt_e1000e->capa.max_input_queues; i++) {
		e1000e_rx_queue_t *rxq = &pkt_e1000e->rx_queues[i];

		if (rxq->rx_data.size)
			mdev_dma_area_free(&pkt_e1000e->mdev, &rxq->rx_data);
	}

	for (i = 0; i < pkt_e1000e->capa.max_output_queues; i++) {
		e1000e_tx_queue_t *txq = &pkt_e1000e->tx_queues[i];

		if (txq->tx_data.size)
			mdev_dma_area_free(&pkt_e1000e->mdev, &txq->tx_data);
	}

	if (pkt_e1000e->sockfd != -1)
		close(pkt_e1000e->sockfd);

	ODP_OPS_DATA_FREE(pkt_e1000e);

	return 0;
}

static void e1000e_rx_refill(e1000e_rx_queue_t *rxq, uint16_t from,
			     uint16_t num)
{
	uint16_t i = from;

	while (num) {
		uint64_t iova = rxq->rx_data.iova + i * E1000E_RX_BUF_SIZE;
		e1000e_rx_desc_t *rxd = &rxq->rx_descs[i];

		rxd->addr = odp_cpu_to_le_64(iova);

		i++;
		if (i >= rxq->rx_queue_len)
			i = 0;

		num--;
	}

	/* Ring the doorbell */
	odpdrv_mmio_u32le_write(i, rxq->doorbell);
}

static int e1000e_recv(pktio_entry_t *pktio_entry, int rxq_idx,
		       odp_packet_t pkt_table[], int num)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;
	e1000e_rx_queue_t *rxq = &pkt_e1000e->rx_queues[rxq_idx];
	uint16_t refill_from;
	uint16_t budget = 0;
	int rx_pkts = 0;
	int ret;

	if (!pkt_e1000e->lockless_rx)
		odp_ticketlock_lock(&rxq->lock);

	/* Keep track of the start point to refill RX queue */
	refill_from = rxq->cidx ? rxq->cidx - 1 : rxq->rx_queue_len - 1;

	/*
	 * Determine how many packets are available in RX queue:
	 *     (Write_index - Read_index) modulo RX queue size
	 */
	budget += odp_le_to_cpu_32(*rxq->pidx);
	budget -= rxq->cidx;
	budget &= rxq->rx_queue_len - 1;

	if (budget > num)
		budget = num;

	ret = odp_packet_alloc_multi(pkt_e1000e->pool, E1000E_RX_BUF_SIZE,
				     pkt_table, budget);
	budget = (ret > 0) ? ret : 0;

	while (rx_pkts < budget) {
		volatile e1000e_rx_desc_t *rxd = &rxq->rx_descs[rxq->cidx];
		odp_packet_hdr_t *pkt_hdr;
		odp_packet_t pkt = pkt_table[rx_pkts];
		uint16_t pkt_len;

		pkt_len = odp_le_to_cpu_16(rxd->length);

		ret = odp_packet_copy_from_mem(pkt, 0, pkt_len,
					       (uint8_t *)rxq->rx_data.vaddr +
					       rxq->cidx * E1000E_RX_BUF_SIZE);
		if (odp_unlikely(ret))
			break;

		pkt_hdr = odp_packet_hdr(pkt);
		pkt_hdr->input = pktio_entry->s.handle;

		rxq->cidx++;
		if (odp_unlikely(rxq->cidx >= rxq->rx_queue_len))
			rxq->cidx = 0;

		rx_pkts++;
	}

	if (rx_pkts)
		e1000e_rx_refill(rxq, refill_from, rx_pkts);

	if (!pkt_e1000e->lockless_rx)
		odp_ticketlock_unlock(&rxq->lock);

	if (rx_pkts < budget)
		odp_packet_free_multi(pkt_table + rx_pkts, budget - rx_pkts);

	return rx_pkts;
}

static int e1000e_send(pktio_entry_t *pktio_entry, int txq_idx,
		       const odp_packet_t pkt_table[], int num)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;
	e1000e_tx_queue_t *txq = &pkt_e1000e->tx_queues[txq_idx];
	uint16_t budget;
	int tx_pkts = 0;

	if (!pkt_e1000e->lockless_tx)
		odp_ticketlock_lock(&txq->lock);

	/* Determine how many packets will fit in TX queue */
	budget = txq->tx_queue_len - 1;
	budget -= txq->pidx;
	budget += odp_le_to_cpu_32(*txq->cidx);
	budget &= txq->tx_queue_len - 1;

	if (budget > num)
		budget = num;

	while (tx_pkts < budget) {
		uint16_t pkt_len = _odp_packet_len(pkt_table[tx_pkts]);
		uint32_t offset = txq->pidx * E1000E_TX_BUF_SIZE;

		e1000e_tx_desc_t *txd = &txq->tx_descs[txq->pidx];

		uint32_t txd_cmd = E1000_TXD_CMD_IFCS | E1000_TXD_CMD_EOP;

		/* Skip oversized packets silently */
		if (odp_unlikely(pkt_len > E1000E_TX_BUF_SIZE)) {
			tx_pkts++;
			continue;
		}

		odp_packet_copy_to_mem(pkt_table[tx_pkts], 0, pkt_len,
				       (uint8_t *)txq->tx_data.vaddr + offset);

		txd->addr = odp_cpu_to_le_64(txq->tx_data.iova + offset);
		txd->cmd = odp_cpu_to_le_32(txd_cmd | pkt_len);

		txq->pidx++;
		if (odp_unlikely(txq->pidx >= txq->tx_queue_len))
			txq->pidx = 0;

		tx_pkts++;
	}

	/* Ring the doorbell */
	if (tx_pkts)
		odpdrv_mmio_u32le_write(txq->pidx, txq->doorbell);

	if (!pkt_e1000e->lockless_tx)
		odp_ticketlock_unlock(&txq->lock);

	odp_packet_free_multi(pkt_table, tx_pkts);

	return tx_pkts;
}

static int e1000e_link_status(pktio_entry_t *pktio_entry)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	return link_status_fd(pkt_e1000e->sockfd, pkt_e1000e->mdev.if_name);
}

static void e1000e_wait_link_up(pktio_entry_t *pktio_entry)
{
	while (!e1000e_link_status(pktio_entry))
		sleep(1);
}

static int e1000e_capability(pktio_entry_t *pktio_entry,
			     odp_pktio_capability_t *capa)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	*capa = pkt_e1000e->capa;
	return 0;
}

static int e1000e_input_queues_config(pktio_entry_t *pktio_entry,
				      const odp_pktin_queue_param_t *p)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_e1000e->lockless_rx = 1;
	else
		pkt_e1000e->lockless_rx = 0;

	return 0;
}

static int e1000e_output_queues_config(pktio_entry_t *pktio_entry,
				       const odp_pktout_queue_param_t *p)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		pkt_e1000e->lockless_tx = 1;
	else
		pkt_e1000e->lockless_tx = 0;

	return 0;
}

static int e1000e_mac_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	pktio_ops_e1000e_data_t *pkt_e1000e = pktio_entry->s.ops_data;

	if (mac_addr_get_fd(pkt_e1000e->sockfd, pkt_e1000e->mdev.if_name,
			    mac_addr) < 0)
		return -1;

	return ETH_ALEN;
}

static int e1000e_init_global(void)
{
	ODP_PRINT("PKTIO: initialized " MODULE_NAME " interface\n");
	return 0;
}

static pktio_ops_module_t e1000e_pktio_ops = {
	.base = {
		 .name = MODULE_NAME,
		 .init_global = e1000e_init_global,
	},

	.open = e1000e_open,
	.close = e1000e_close,

	.recv = e1000e_recv,
	.send = e1000e_send,

	.link_status = e1000e_link_status,

	.capability = e1000e_capability,

	.mac_get = e1000e_mac_get,

	.input_queues_config = e1000e_input_queues_config,
	.output_queues_config = e1000e_output_queues_config,
};

/** e1000e module entry point */
ODP_MODULE_CONSTRUCTOR(e1000e_pktio_ops)
{
	odp_module_constructor(&e1000e_pktio_ops);

	odp_subsystem_register_module(pktio_ops, &e1000e_pktio_ops);
}

/*
 * Temporary variable to enable link this module,
 * will remove in Makefile scheme changes.
 */
int enable_link_e1000e_pktio_ops;

#endif /* ODP_MDEV */
