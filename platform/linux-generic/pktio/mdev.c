/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#if defined(ODP_MDEV) && ODP_MDEV == 1

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/vfio.h>

#include <odp_posix_extensions.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>

#include <odp/api/hints.h>

#include <pktio/mdev.h>
#include <pktio/uapi_net_mdev.h>

/**
 * returns a valid VFIO container
 * fd must be closed by caller
 */
static int get_container(void)
{
	int container;
	int ret;

	/* Create a new container */
	container = open("/dev/vfio/vfio", O_RDWR);
	if (container < 0) {
		ODP_ERR("Failed to create new VFIO container\n");
		goto out;
	}

	ret = ioctl(container, VFIO_GET_API_VERSION);
	if (ret != VFIO_API_VERSION) {
		ODP_ERR("VFIO API version mismatch: expected %i, got %i\n",
			VFIO_API_VERSION, ret);
		goto out;
	}

	ret = ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
	if (!ret) {
		ODP_ERR("Container doesn't support VFIO_TYPE1_IOMMU\n");
		goto out;
	}

	return container;

out:
	if (container != -1)
		close(container);
	return -1;
}

/**
 * returns a valid VFIO group
 * fd must be closed by caller
 */
static int get_group(int grp_id)
{
	char path[32];
	int group;
	int ret;
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status)
	};

	snprintf(path, sizeof(path), "/dev/vfio/%d", grp_id);
	group = open(path, O_RDWR);
	if (group < 0) {
		ODP_ERR("Failed to open %s: %s\n", path, strerror(errno));
		goto out;
	}

	ret = ioctl(group, VFIO_GROUP_GET_STATUS, &group_status);
	if (ret < 0) {
		ODP_ERR("Failed to get group status\n");
		goto out;
	}

	/* Test the group is viable and available */
	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		ODP_ERR("Group is not viable\n");
		goto out;
	}

	return group;

out:
	if (group != -1)
		close(group);
	return -1;
}

static void vfio_find_sparse_mmaps(struct vfio_info_cap_header *hdr,
				   struct vfio_region_info_cap_sparse_mmap
				   **sparse)
{
	*sparse =
	    odp_container_of(hdr, struct vfio_region_info_cap_sparse_mmap,
			     header);
}

static struct vfio_info_cap_header *
vfio_get_region_info_cap(struct vfio_region_info *info, __u16 id)
{
	struct vfio_info_cap_header *hdr;
	void *ptr = info;

	if (!(info->flags & VFIO_REGION_INFO_FLAG_CAPS))
		return NULL;

	for (hdr =
	     (struct vfio_info_cap_header *)(void *)((uint8_t *)ptr
						     + info->cap_offset);
	     hdr != ptr;
	     hdr = (struct vfio_info_cap_header *)(void *)((uint8_t *)ptr
							   + hdr->next)) {
		if (hdr->id == id)
			return hdr;
	}

	return NULL;
}

static struct vfio_info_cap_header *
vfio_get_cap_info(struct vfio_region_info *region_info, __u16 id)
{
	struct vfio_info_cap_header *caps = NULL;

	caps = vfio_get_region_info_cap(region_info, id);

	return caps;
}

int vfio_get_region_sparse_mmaps(struct vfio_region_info *region_info,
				 struct vfio_region_info_cap_sparse_mmap
				 **sparse)
{
	struct vfio_info_cap_header *caps = NULL;
	int ret = -ENOENT;

	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		caps = vfio_get_cap_info(region_info,
					 VFIO_REGION_INFO_CAP_SPARSE_MMAP);
		if (!caps)
			goto out;
		vfio_find_sparse_mmaps(caps, sparse);
		if (*sparse) {
			for (uint32_t i = 0; i < (*sparse)->nr_areas; i++)
				ODP_DBG("Sparse region: %d 0x%llx %llu\n", i,
					(*sparse)->areas[i].offset,
					(*sparse)->areas[i].size);
		}

		ret = 0;
	}

out:
	return ret;
}

/** Match capability type
 * returns 0 on succcess
 */
int vfio_get_region_cap_type(struct vfio_region_info *region_info,
			     mdev_region_class_t *class_info)
{
	struct vfio_info_cap_header *caps = NULL;
	int ret = 0;
	struct vfio_region_info_cap_type *cap_type;

	if (region_info->flags & VFIO_REGION_INFO_FLAG_CAPS &&
	    region_info->argsz > sizeof(*region_info)) {
		caps = vfio_get_cap_info(region_info,
					 VFIO_REGION_INFO_CAP_TYPE);
		if (!caps) {
			ret = -EINVAL;
			goto out;
		}

		cap_type =
		    odp_container_of(caps, struct vfio_region_info_cap_type,
				     header);

		class_info->type = cap_type->type;
		class_info->subtype = cap_type->subtype;
	}
out:
	return ret;
}

/**
 * Get specific region info
 */
static struct vfio_region_info *vfio_get_region(mdev_device_t *mdev,
						__u32 region)
{
	int ret;
	struct vfio_region_info *region_info = NULL;

	ODP_DBG("Region:%d\n", region);
	region_info = calloc(1, sizeof(*region_info));
	if (!region_info)
		goto out;

	region_info->index = region;
	region_info->argsz = sizeof(*region_info);
	ret = ioctl(mdev->device, VFIO_DEVICE_GET_REGION_INFO, region_info);
	if (ret < 0) {
		ODP_ERR("Failed to get PCI region info\n");
		goto out;
	}

	if (region_info->argsz > sizeof(*region_info)) {
		struct vfio_region_info *tmp;

		tmp = realloc(region_info, region_info->argsz);
		if (!tmp)
			goto out;

		region_info = tmp;

		ODP_DBG("region info %d with extended capabilities size: %u\n",
			region, region_info->argsz);
		ret = ioctl(mdev->device, VFIO_DEVICE_GET_REGION_INFO,
			    region_info);
		if (ret < 0) {
			ODP_ERR("Failed to get PCI region info\n");
			goto out;
		}
	}

	if (!region_info->size) {
		ODP_DBG("region info %d is empty, skipping\n", region);
		goto out;
	}

	return region_info;

out:
	if (region_info)
		free(region_info);
	return NULL;
}

/**
 * mmap a VFIO region
 */
void *mdev_region_mmap(mdev_device_t *mdev, uint64_t offset, uint64_t size)
{
	void *addr;

	/* Make sure we're page aligned */
	ODP_ASSERT(offset == ROUNDUP_ALIGN(offset, ODP_PAGE_SIZE));
	ODP_ASSERT(size == ROUNDUP_ALIGN(size, ODP_PAGE_SIZE));

	if (mdev->mappings_count >= ARRAY_SIZE(mdev->mappings))
		return MAP_FAILED;

	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
		    mdev->device, offset);
	if (addr == MAP_FAILED)
		return addr;

	mdev->mappings[mdev->mappings_count].addr = addr;
	mdev->mappings[mdev->mappings_count].size = size;
	mdev->mappings_count++;

	return addr;
}

int mdev_dma_area_alloc(mdev_device_t *mdev, mdev_dma_area_t *dma_area)
{
	struct vfio_iommu_type1_dma_map req;
	void *tmp;

	/* Make sure we're page aligned */
	if (dma_area->size != ROUNDUP_ALIGN(dma_area->size, ODP_PAGE_SIZE))
		return -EINVAL;

	memset(&req, 0, sizeof(req));
	req.argsz = sizeof(req);

	tmp = mmap(NULL, dma_area->size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED, -1,
		   0);
	if (tmp == MAP_FAILED) {
		ODP_ERR("mmap failed\n");
		return -EFAULT;
	}

	dma_area->vaddr = (uint64_t)tmp;

	req.vaddr = dma_area->vaddr;
	req.size = dma_area->size;
	req.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	if (ioctl(mdev->device, VFIO_IOMMU_MAP_DMA, &req) < 0) {
		ODP_ERR("ioctl failed\n");
		return -EFAULT;
	}

	dma_area->iova = req.iova;

	ODP_DBG("dma_area alloc: %llx@%llx -> %llx\n", dma_area->size,
		dma_area->vaddr, dma_area->iova);

	return 0;
}

int mdev_dma_area_free(mdev_device_t *mdev, mdev_dma_area_t *dma_area)
{
	struct vfio_iommu_type1_dma_unmap req;

	memset(&req, 0, sizeof(req));
	req.argsz = sizeof(req);
	req.iova = dma_area->iova;
	req.size = dma_area->size;
	req.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;

	if (ioctl(mdev->device, VFIO_IOMMU_UNMAP_DMA, &req) < 0) {
		ODP_ERR("ioctl failed\n");
		return -EFAULT;
	}

	if (munmap((void *)dma_area->vaddr, dma_area->size) < 0) {
		ODP_ERR("munmap failed\n");
		return -EFAULT;
	}

	ODP_DBG("dma_area free: %llx@%llx -> %llx\n", dma_area->size,
		dma_area->vaddr, dma_area->iova);

	return 0;
}

static char *mdev_basename(char *path)
{
	char *rpath;

	rpath = basename(path);
	if (rpath)
		return rpath;

	return NULL;
}

static int mdev_readlink(const char *path, char *link, size_t linksz)
{
	ssize_t len;

	len = readlink(path, link, linksz - 1);
	if (len != -1) {
		link[len] = '\0';
		return 0;
	}
	return -1;
}

/**
 * returns group_id or -1 on fail and fills group_uuid
 */
static int mdev_sysfs_discover(const char *mod_name, const char *if_name,
			       char *uuid, size_t sz)
{
	int ret;
	char *driver, *iommu_group;
	char sysfs_path[2048], sysfs_link[2048];
	DIR *dir;
	struct dirent *dp;

	/* Don't put / on the end of the path */
	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/net/%s/device/driver", if_name);
	ret = mdev_readlink(sysfs_path, sysfs_link, sizeof(sysfs_link));
	if (ret) {
		ODP_ERR("Can't locate sysfs driver path\n");
		return -1;
	}

	driver = mdev_basename(sysfs_link);
	if (!driver) {
		ODP_ERR("Can't driver in sysfs\n");
		return -1;
	}

	if (strcmp(driver, mod_name)) {
		ODP_ERR("Invalid driver name\n");
		return -1;
	}

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/class/net/%s/device/mdev_supported_types/%s-netmdev/devices/",
		 if_name, driver);

	dir = opendir(sysfs_path);
	if (!dir)
		return -1;

	/* We assume only one UUID per network interface */
	uuid[0] = '\0';
	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") && strcmp(dp->d_name, "..")) {
			strncpy(uuid, dp->d_name, sz);
			break;
		}
	}
	closedir(dir);

	if (uuid[0] == '\0')
		return -1;

	snprintf(sysfs_path, sizeof(sysfs_path),
		 "/sys/bus/mdev/devices/%s/iommu_group", uuid);
	ret = mdev_readlink(sysfs_path, sysfs_link, sizeof(sysfs_link));
	if (ret) {
		ODP_ERR("Can't locate IOMMU sysfs path\n");
		return -1;
	}

	iommu_group = mdev_basename(sysfs_link);
	if (!iommu_group) {
		ODP_ERR("Can't locate iommu group in sysfs\n");
		return -1;
	}
	ret = atoi(iommu_group);

	return ret;
}

/**
 * Initialize VFIO variables.
 * set IOMMU and get device regions
 */
static int vfio_init_dev(int grp, int container,
			 struct vfio_group_status *grp_status,
			 struct vfio_iommu_type1_info *iommu_info,
			 struct vfio_device_info *dev_info, char *grp_uuid)
{
	int device = -1;
	int ret;

	ret = ioctl(container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU);
	if (ret < 0) {
		ODP_ERR("Doesn't support the IOMMU driver we want\n");
		goto out;
	}

	/* Test the group is viable and available */
	ret = ioctl(grp, VFIO_GROUP_GET_STATUS, grp_status);
	if (ret < 0 || !(grp_status->flags & VFIO_GROUP_FLAGS_VIABLE)) {
		ODP_ERR("Can't get status\n");
		goto out;
	}

	ret = ioctl(grp, VFIO_GROUP_SET_CONTAINER, &container);
	if (ret < 0) {
		ODP_ERR("Failed to set container\n");
		goto out;
	}

	ret = ioctl(container, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
	if (ret < 0) {
		ODP_ERR("Failed to set IOMMU\n");
		goto out;
	}

	ret = ioctl(container, VFIO_IOMMU_GET_INFO, iommu_info);
	if (ret < 0) {
		ODP_ERR("Failed to get IOMMU info\n");
		goto out;
	}

	ODP_DBG("iova_pgsizes bitmask=0x%llx\n", iommu_info->iova_pgsizes);
	/* Get a file descriptor for the device */
	device = ioctl(grp, VFIO_GROUP_GET_DEVICE_FD, grp_uuid);
	if (device < 0) {
		ODP_ERR("Failed to get device FD\n");
		goto out;
	}

	/* Test and setup the device */
	ret = ioctl(device, VFIO_DEVICE_GET_INFO, dev_info);
	if (ret < 0) {
		ODP_ERR("Failed to get device info\n");
		goto out;
	}

	ODP_DBG("Device %d Regions: %d, irqs:%d\n", device,
		dev_info->num_regions, dev_info->num_irqs);

	return device;

out:
	return -1;
}

int mdev_device_create(mdev_device_t *mdev, const char *mod_name,
		       const char *if_name,
		       mdev_region_info_cb_t region_info_cb)
{
	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status)
	};
	struct vfio_iommu_type1_info iommu_info = {
		.argsz = sizeof(iommu_info)
	};
	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info)
	};
	int ret;

	memset(mdev, 0, sizeof(*mdev));
	mdev->container = -1;
	mdev->group = -1;

	strncpy(mdev->if_name, if_name, sizeof(mdev->if_name) - 1);

	mdev->group_id =
	    mdev_sysfs_discover(mod_name, mdev->if_name, mdev->group_uuid,
				sizeof(mdev->group_uuid));
	if (mdev->group_id < 0)
		goto fail;

	mdev->container = get_container();
	if (mdev->container < 0)
		goto fail;

	mdev->group = get_group(mdev->group_id);
	if (mdev->group < 0)
		goto fail;

	mdev->device =
	    vfio_init_dev(mdev->group, mdev->container, &group_status,
			  &iommu_info, &device_info, mdev->group_uuid);
	if (mdev->device < 0)
		goto fail;

	ret = -EINVAL;
	for (uint32_t region = 0; region < device_info.num_regions; region++) {
		struct vfio_region_info *region_info;

		region_info = vfio_get_region(mdev, region);
		if (!region_info)
			continue;

		ret = region_info_cb(mdev, region_info);
		free(region_info);
		if (ret < 0) {
			ODP_ERR("Region info cb fail on region_info[%u]\n",
				region);
			return -1;
		}

		ret = 0;
	}

	return ret;

fail:
	return -1;
}

void mdev_device_destroy(mdev_device_t *mdev)
{
	if (mdev->group != -1)
		close(mdev->group);
	if (mdev->container != -1)
		close(mdev->container);

	for (uint16_t i = 0; i < mdev->mappings_count; i++)
		munmap(mdev->mappings[i].addr, mdev->mappings[i].size);
}

#endif /* ODP_MDEV */
