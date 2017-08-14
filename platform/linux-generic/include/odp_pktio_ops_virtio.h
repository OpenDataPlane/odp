/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_VIRTIO_H
#define ODP_PACKET_VIRTIO_H

#include <drv_pci_internal.h>

typedef struct {
	struct pci_dev_t *pci_dev;
	int dev_id;
	char name[32]; /**< Unique identifier name */
} pktio_ops_virtio_data_t;

#endif
