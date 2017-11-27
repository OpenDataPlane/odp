/*
 * Copyright (c) 2017, Linaro Limited
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * devices are spcified as: pci:domain:bus:device.function
 */

#include "config.h"

#ifdef ODP_PKTIO_VIRTIO

#include <stdio.h>

#include <odp_api.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>

#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>

#include <drv_pci_internal.h>
#include <odp_pktio_ops_virtio.h>

#include "virtio_pci.h"

#define PCI_PKTIO_PREFIX "pci:"
#define PCI_PKTIO_PREFIX_LEN (sizeof(PCI_PKTIO_PREFIX) - 1)

/* FIXME: this should be registered as a DevIO */
extern const user_access_ops_t uio_access_ops;

static int virtio_init_global(void)
{
	ODP_PRINT("PKTIO: initialized pci interface.\n");
	return 0;
}

static int virtio_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		       const char *devname, odp_pool_t pool ODP_UNUSED)
{
	static unsigned int dev_id = 0;
	pktio_ops_virtio_data_t *virtio_entry;
	const char *pci_device;
	pci_dev_t *pci_dev;

	if (strncmp(devname, PCI_PKTIO_PREFIX, PCI_PKTIO_PREFIX_LEN))
		return -1;

	virtio_entry = ODP_OPS_DATA_ALLOC(sizeof(*virtio_entry));
	if (virtio_entry == NULL)
		return -2;

	pci_device = devname + PCI_PKTIO_PREFIX_LEN;

	ODP_PRINT("virtio_open: %s\n", pci_device);

	pci_dev = pci_open_device(pci_device);
	if (pci_dev == NULL) {
		ODP_ERR("pci: could not open PCI device %s as a VirtIO device\n",
			pci_device);
		ODP_OPS_DATA_FREE(virtio_entry);
		return -1;
	}

	if (virtio_pci_init(pci_dev)) {
		ODP_ERR("virtio: Could not open device %s\n", devname);
		pci_close_device(pci_dev);
		ODP_OPS_DATA_FREE(virtio_entry);
		return -1;
	}

	memset(virtio_entry, 0, sizeof(pktio_ops_virtio_data_t));
	snprintf(virtio_entry->name, sizeof(virtio_entry->name),
		 "virtio_%u", dev_id++);
	virtio_entry->pci_dev = pci_dev;

	pktio_entry->s.ops_data = virtio_entry;

	ODP_PRINT("virtio: opened %s\n", virtio_entry->name);

	return 0;
}

static int virtio_close(pktio_entry_t *pktio_entry)
{
	pktio_ops_virtio_data_t *virtio_entry = pktio_entry->s.ops_data;

	if (virtio_entry == NULL)
		return 0;

	pci_close_device(virtio_entry->pci_dev);
	ODP_OPS_DATA_FREE(virtio_entry);

	return 0;
}

static int virtio_recv(pktio_entry_t *pktio_entry ODP_UNUSED, int index ODP_UNUSED,
		       odp_packet_t pkts[] ODP_UNUSED, int len ODP_UNUSED)
{
	return 0;
}

static int virtio_send(pktio_entry_t *pktio_entry ODP_UNUSED, int index ODP_UNUSED,
		       const odp_packet_t pkt_tbl[] ODP_UNUSED, int len)
{
	return len;
}

static pktio_ops_module_t virtio_pktio_ops = {
	.base = {
		.name = "virtio-net",
		.init_local = NULL,
		.term_local = NULL,
		.init_global = virtio_init_global,
		.term_global = NULL,
	},
	.open = virtio_open,
	.close = virtio_close,
	.start = NULL,
	.stop = NULL,
	.stats = NULL,
	.stats_reset = NULL,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.recv = virtio_recv,
	.send = virtio_send,
	.mtu_get = NULL,
	.promisc_mode_set = NULL,
	.promisc_mode_get = NULL,
	.mac_get = NULL,
	.link_status = NULL,
	.capability = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
	.print = NULL,
};

ODP_MODULE_CONSTRUCTOR(virtio_pktio_ops)
{
	odp_module_constructor(&virtio_pktio_ops);

	odp_subsystem_register_module(pktio_ops, &virtio_pktio_ops);
}

/* Temporary variable to enable linking this module in,
 * shall be removed later
 */
int enable_link_virtio_pktio_ops = 0;

#endif
