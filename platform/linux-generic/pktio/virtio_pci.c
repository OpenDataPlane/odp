/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#ifdef ODP_PKTIO_VIRTIO

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

#include <config.h>
#include <odp_drv.h>
#include <odp_debug_internal.h>
#include <drv_pci_internal.h>

#include "virtio_pci.h"

/* Features desired/implemented by this driver. */
#define VIRTIO_NET_DRIVER_FEATURES              \
	(1u << VIRTIO_NET_F_MAC           |     \
	 1u << VIRTIO_NET_F_STATUS        |     \
	 1u << VIRTIO_NET_F_MQ            |     \
	 1u << VIRTIO_NET_F_CTRL_MAC_ADDR |     \
	 1u << VIRTIO_NET_F_CTRL_VQ       |     \
	 1u << VIRTIO_NET_F_CTRL_RX       |     \
	 1u << VIRTIO_NET_F_CTRL_VLAN     |     \
	 1u << VIRTIO_NET_F_MRG_RXBUF     |     \
	 1ULL << VIRTIO_F_VERSION_1)

static void virtio_print_features(const struct virtio_hw *hw)
{
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CSUM))
		ODP_PRINT("VIRTIO_NET_F_CSUM\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_CSUM))
		ODP_PRINT("VIRTIO_NET_F_GUEST_CSUM\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MAC))
		ODP_PRINT("VIRTIO_NET_F_MAC\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO4))
		ODP_PRINT("VIRTIO_NET_F_GUEST_TSO4\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_TSO6))
		ODP_PRINT("VIRTIO_NET_F_GUEST_TSO6\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_ECN))
		ODP_PRINT("VIRTIO_NET_F_GUEST_ECN\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_UFO))
		ODP_PRINT("VIRTIO_NET_F_GUEST_UFO\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_HOST_TSO4))
		ODP_PRINT("VIRTIO_NET_F_HOST_TSO4\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_HOST_TSO6))
		ODP_PRINT("VIRTIO_NET_F_HOST_TSO6\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_HOST_ECN))
		ODP_PRINT("VIRTIO_NET_F_HOST_ECN\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_HOST_UFO))
		ODP_PRINT("VIRTIO_NET_F_HOST_UFO\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF))
		ODP_PRINT("VIRTIO_NET_F_MRG_RXBUF\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_STATUS))
		ODP_PRINT("VIRTIO_NET_F_STATUS\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VQ))
		ODP_PRINT("VIRTIO_NET_F_CTRL_VQ\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_RX))
		ODP_PRINT("VIRTIO_NET_F_CTRL_RX\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_VLAN))
		ODP_PRINT("VIRTIO_NET_F_CTRL_VLAN\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_RX_EXTRA))
		ODP_PRINT("VIRTIO_NET_F_CTRL_RX_EXTRA\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_GUEST_ANNOUNCE))
		ODP_PRINT("VIRTIO_NET_F_GUEST_ANNOUNCE\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MQ))
		ODP_PRINT("VIRTIO_NET_F_MQ\n");
	if (vtpci_with_feature(hw, VIRTIO_NET_F_CTRL_MAC_ADDR))
		ODP_PRINT("VIRTIO_NET_F_CTRL_MAC_ADDR\n");
}

static inline uint8_t io_read8(uint8_t *addr)
{
	return *(volatile uint8_t *)addr;
}

static inline void io_write8(uint8_t val, uint8_t *addr)
{
	*(volatile uint8_t *)addr = val;
}

static inline uint16_t io_read16(uint16_t *addr)
{
	return *(volatile uint16_t *)addr;
}

static inline void io_write16(uint16_t val, uint16_t *addr)
{
	*(volatile uint16_t *)addr = val;
}

static inline uint32_t io_read32(uint32_t *addr)
{
	return *(volatile uint32_t *)addr;
}

static inline void io_write32(uint32_t val, uint32_t *addr)
{
	*(volatile uint32_t *)addr = val;
}

static inline void io_write64_twopart(uint64_t val, uint32_t *lo, uint32_t *hi)
{
	io_write32(val & ((1ULL << 32) - 1), lo);
	io_write32(val >> 32,		     hi);
}

static void modern_read_dev_config(struct virtio_hw *hw, size_t offset,
				   void *dst, int length)
{
	int i;
	uint8_t *p;
	uint8_t old_gen, new_gen;

	do {
		old_gen = io_read8(&hw->common_cfg->config_generation);

		p = dst;
		for (i = 0;  i < length; i++)
			*p++ = io_read8((uint8_t *)hw->dev_cfg + offset + i);

		new_gen = io_read8(&hw->common_cfg->config_generation);
	} while (old_gen != new_gen);
}

static void modern_write_dev_config(struct virtio_hw *hw, size_t offset,
				    const void *src, int length)
{
	int i;
	const uint8_t *p = src;

	for (i = 0;  i < length; i++)
		io_write8(*p++, (uint8_t *)hw->dev_cfg + offset + i);
}

static uint64_t modern_get_features(struct virtio_hw *hw)
{
	uint32_t features_lo, features_hi;

	io_write32(0, &hw->common_cfg->device_feature_select);
	features_lo = io_read32(&hw->common_cfg->device_feature);

	io_write32(1, &hw->common_cfg->device_feature_select);
	features_hi = io_read32(&hw->common_cfg->device_feature);

	return ((uint64_t)features_hi << 32) | features_lo;
}

static void modern_set_features(struct virtio_hw *hw, uint64_t features)
{
	io_write32(0, &hw->common_cfg->guest_feature_select);
	io_write32(features & ((1ULL << 32) - 1),
		&hw->common_cfg->guest_feature);

	io_write32(1, &hw->common_cfg->guest_feature_select);
	io_write32(features >> 32,
		&hw->common_cfg->guest_feature);
}

static uint8_t modern_get_status(struct virtio_hw *hw)
{
	return io_read8(&hw->common_cfg->device_status);
}

static void modern_set_status(struct virtio_hw *hw, uint8_t status)
{
	io_write8(status, &hw->common_cfg->device_status);
}

static void modern_reset(struct virtio_hw *hw)
{
	modern_set_status(hw, VIRTIO_CONFIG_STATUS_RESET);
	modern_get_status(hw);
}

static uint8_t modern_get_isr(struct virtio_hw *hw)
{
	return io_read8(hw->isr);
}

static uint16_t modern_set_config_irq(struct virtio_hw *hw, uint16_t vec)
{
	io_write16(vec, &hw->common_cfg->msix_config);
	return io_read16(&hw->common_cfg->msix_config);
}

static uint16_t modern_get_queue_num(struct virtio_hw *hw, uint16_t queue_id)
{
	io_write16(queue_id, &hw->common_cfg->queue_select);
	return io_read16(&hw->common_cfg->queue_size);
}

static int modern_setup_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	(void)hw;
	(void)vq;
	return 0;
}

static void modern_del_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	(void)hw;
	(void)vq;
}

static void modern_notify_queue(struct virtio_hw *hw, struct virtqueue *vq)
{
	(void)hw;
	(void)vq;
}

static const struct virtio_pci_ops modern_ops = {
	.read_dev_cfg	= modern_read_dev_config,
	.write_dev_cfg	= modern_write_dev_config,
	.reset		= modern_reset,
	.get_status	= modern_get_status,
	.set_status	= modern_set_status,
	.get_features	= modern_get_features,
	.set_features	= modern_set_features,
	.get_isr	= modern_get_isr,
	.set_config_irq	= modern_set_config_irq,
	.get_queue_num	= modern_get_queue_num,
	.setup_queue	= modern_setup_queue,
	.del_queue	= modern_del_queue,
	.notify_queue	= modern_notify_queue,
};


void vtpci_read_dev_config(struct virtio_hw *hw, size_t offset,
			   void *dst, int length)
{
	hw->vtpci_ops->read_dev_cfg(hw, offset, dst, length);
}

void vtpci_write_dev_config(struct virtio_hw *hw, size_t offset,
			    const void *src, int length)
{
	hw->vtpci_ops->write_dev_cfg(hw, offset, src, length);
}

uint64_t vtpci_negotiate_features(struct virtio_hw *hw, uint64_t host_features)
{
	uint64_t features;

	/*
	 * Limit negotiated features to what the driver, virtqueue, and
	 * host all support.
	 */
	features = host_features & hw->guest_features;
	hw->vtpci_ops->set_features(hw, features);

	return features;
}

void vtpci_reset(struct virtio_hw *hw)
{
	hw->vtpci_ops->set_status(hw, VIRTIO_CONFIG_STATUS_RESET);
	/* flush status write */
	hw->vtpci_ops->get_status(hw);
}

void vtpci_reinit_complete(struct virtio_hw *hw)
{
	vtpci_set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER_OK);
}

void vtpci_set_status(struct virtio_hw *hw, uint8_t status)
{
	if (status != VIRTIO_CONFIG_STATUS_RESET)
		status |= hw->vtpci_ops->get_status(hw);

	hw->vtpci_ops->set_status(hw, status);
}

uint8_t vtpci_get_status(struct virtio_hw *hw)
{
	return hw->vtpci_ops->get_status(hw);
}

uint8_t vtpci_isr(struct virtio_hw *hw)
{
	return hw->vtpci_ops->get_isr(hw);
}


/* Enable one vector (0) for Link State Intrerrupt */
uint16_t vtpci_irq_config(struct virtio_hw *hw, uint16_t vec)
{
	return hw->vtpci_ops->set_config_irq(hw, vec);
}

static void *get_cfg_addr(pci_dev_t *dev, struct virtio_pci_cap *cap)
{
	uint8_t  bar    = cap->bar;
	uint32_t length = cap->length;
	uint32_t offset = cap->offset;
	uint8_t *base;

	if (bar > 5) {
		ODP_ERR("invalid bar: %u\n", bar);
		return NULL;
	}

	if (offset + length < offset) {
		ODP_ERR("offset(%u) + length(%u) overflows\n",
			offset, length);
		return NULL;
	}

	if (offset + length > dev->bar[bar].len) {
		ODP_ERR("invalid cap: overflows bar space: %u > %\n" PRIu64,
			offset + length, dev->bar[bar].len);
		return NULL;
	}

	base = dev->bar[bar].addr;
	if (base == NULL) {
		ODP_ERR("bar %u base addr is NULL\n", bar);
		return NULL;
	}

	return base + offset;
}

static int virtio_read_caps(pci_dev_t *dev, struct virtio_hw *hw)
{
	uint8_t pos;
	struct virtio_pci_cap cap;
	int ret;

	if (dev->user_access_ops->map_resource(dev)) {
		ODP_DBG("failed to map pci device!\n");
		return -1;
	}

	ret = pci_read_config(dev, &pos, 1, PCI_CAPABILITY_LIST);
	if (ret < 0) {
		ODP_DBG("failed to read pci capability list\n");
		return -1;
	}

	while (pos) {
		ret = pci_read_config(dev, &cap, sizeof(cap), pos);
		if (ret < 0) {
			ODP_ERR("failed to read pci cap at pos: %x\n", pos);
			break;
		}

		if (cap.cap_vndr != PCI_CAP_ID_VNDR) {
			ODP_DBG("[%2x] skipping non VNDR cap id: %02x\n",
				pos, cap.cap_vndr);
			goto next;
		}

		ODP_DBG("[%2x] cfg type: %u, bar: %u, offset: %04x, len: %u\n",
			pos, cap.cfg_type, cap.bar, cap.offset, cap.length);

		switch (cap.cfg_type) {
		case VIRTIO_PCI_CAP_COMMON_CFG:
			hw->common_cfg = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_NOTIFY_CFG:
			pci_read_config(dev, &hw->notify_off_multiplier,
					4, pos + sizeof(cap));
			hw->notify_base = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_DEVICE_CFG:
			hw->dev_cfg = get_cfg_addr(dev, &cap);
			break;
		case VIRTIO_PCI_CAP_ISR_CFG:
			hw->isr = get_cfg_addr(dev, &cap);
			break;
		}

next:
		pos = cap.cap_next;
	}

	if (hw->common_cfg == NULL || hw->notify_base == NULL ||
	    hw->dev_cfg == NULL    || hw->isr == NULL) {
		ODP_DBG("no modern virtio pci device found.\n");
		return -1;
	}

	ODP_DBG("found modern virtio pci device.\n");

	ODP_DBG("common cfg mapped at: %p\n", hw->common_cfg);
	ODP_DBG("device cfg mapped at: %p\n", hw->dev_cfg);
	ODP_DBG("isr cfg mapped at: %p\n", hw->isr);
	ODP_DBG("notify base: %p, notify off multiplier: %u\n",
		hw->notify_base, hw->notify_off_multiplier);

	return 0;
}

static void virtio_get_hwaddr(struct virtio_hw *hw)
{
	if (vtpci_with_feature(hw, VIRTIO_NET_F_MAC)) {
		vtpci_read_dev_config(hw,
				      ODPDRV_OFFSETOF(struct virtio_net_config,
						      mac),
				      &hw->mac_addr,
				      6);
		ODP_PRINT("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			  hw->mac_addr[0],
			  hw->mac_addr[1],
			  hw->mac_addr[2],
			  hw->mac_addr[3],
			  hw->mac_addr[4],
			  hw->mac_addr[5]);
	} else {
		ODP_PRINT("No support for VIRTIO_NET_F_MAC\n");
	}
}

static int virtio_init_ethdev(struct virtio_hw *hw)
{
	const struct virtio_pci_ops *ops = hw->vtpci_ops;
	uint64_t device_features = 0;

	ODP_PRINT("Init VirtIO Net device\n");

	ops->reset(hw);
	ops->set_status(hw, VIRTIO_CONFIG_STATUS_ACK);
	ops->set_status(hw, VIRTIO_CONFIG_STATUS_DRIVER);
	device_features = ops->get_features(hw);

	/* accept only those feature this driver also supports */
	hw->guest_features = device_features & VIRTIO_NET_DRIVER_FEATURES;

	if (!vtpci_with_feature(hw, VIRTIO_F_VERSION_1)) {
		ODP_ERR("VirtIO device does not comply with VirtIO 1.0 spec\n");
		return -1;
	}

	ops->set_features(hw, hw->guest_features);
	virtio_print_features(hw);

	ops->set_status(hw, VIRTIO_CONFIG_STATUS_FEATURES_OK);
	if (!(ops->get_status(hw) & VIRTIO_CONFIG_STATUS_FEATURES_OK)) {
		ODP_ERR("VirtIO device error negotiationg features\n");
		return -1;
	}

	virtio_get_hwaddr(hw);

	return 0;
}

/* FIXME: this should be registered as a DevIO */
extern const user_access_ops_t uio_access_ops;

/*
 * Return -1:
 *   if there is error mapping with VFIO/UIO.
 *   if port map error when driver type is KDRV_NONE.
 *   if whitelisted but driver type is KDRV_UNKNOWN.
 * Return 1 if kernel driver is managing the device.
 * Return 0 on success.
 */
int virtio_pci_init(pci_dev_t *dev)
{
	struct virtio_hw *hw = NULL;

	if (dev->id.vendor_id != VIRTIO_PCI_VENDOR_ID)
		return -1;

	if (dev->id.device_id != VIRTIO_PCI_LEGACY_DEVICE_ID_NET &&
	    dev->id.device_id != VIRTIO_PCI_MODERN_DEVICE_ID_NET)
		return -1;

	hw = malloc(sizeof(struct virtio_hw));
	if (hw == NULL)
		return -1;
	memset(hw, 0, sizeof(struct virtio_hw));

	/* Find suitable DevIO module that works with this device */
	if (dev->kdrv == PCI_KDRV_UIO_GENERIC) {
		/* probing would be done for each possible DevIO */
		if (uio_access_ops.probe(dev) != 0)
			goto err_free;
		dev->user_access_ops = &uio_access_ops;
	} else {
		ODP_ERR("Could not find suitable DevIO for device\n");
		goto err_free;
	}

	/*
	 * Try if we can succeed reading virtio pci caps, which exists
	 * only on modern pci device.
	 */
	if (virtio_read_caps(dev, hw) != 0) {
		/* we only support modern interface */
		ODP_ERR("virtio_pci: could not read device capabilities\n");
		goto err_free;
	}

	hw->dev = dev;
	hw->vtpci_ops = &modern_ops;
	hw->modern    = 1;
	if (virtio_init_ethdev(hw) != 0)
		goto err_free;
	dev->driver_data = (void *)hw;

	return 0;

err_free:
	free(hw);
	return -1;
}

#endif
