/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PKTIO_MDEV_H_
#define ODP_PKTIO_MDEV_H_

#include <linux/vfio.h>
#include <net/if.h>

#define NET_MDEV_PREFIX "mdev:"

typedef struct {
	uint16_t type;
	uint16_t subtype;
} mdev_region_class_t;

typedef struct {
	uint64_t vaddr;
	uint64_t iova;
	uint64_t size;
} mdev_dma_area_t;

typedef struct {
	char if_name[IF_NAMESIZE];	/**< Interface name */

	int container;
	int group;
	int device;

	int group_id;
	char group_uuid[64];

	struct {
		uint8_t *addr;
		size_t size;
	} mappings[256];
	uint16_t mappings_count;
} mdev_device_t;

typedef int (*mdev_region_info_cb_t)(mdev_device_t *,
				     struct vfio_region_info *);

int mdev_device_create(mdev_device_t *mdev, const char *mod_name,
		       const char *if_name, mdev_region_info_cb_t cb);
void mdev_device_destroy(mdev_device_t *mdev);

void *mdev_region_mmap(mdev_device_t *mdev, uint64_t offset, uint64_t size);

int vfio_get_region_cap_type(struct vfio_region_info *region_info,
			     mdev_region_class_t *type_info);
int vfio_get_region_sparse_mmaps(struct vfio_region_info *region_info,
				 struct vfio_region_info_cap_sparse_mmap
				 **sparse);

int mdev_dma_area_alloc(mdev_device_t *mdev, mdev_dma_area_t *dma_area);
int mdev_dma_area_free(mdev_device_t *mdev, mdev_dma_area_t *dma_area);

#endif
