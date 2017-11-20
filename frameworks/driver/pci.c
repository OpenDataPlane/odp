/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* Many of this functions have been inspired by their dpdk counterpart,
 * hence the following license:
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 */

/**
 * @file
 * PCI interface for drivers
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <linux/limits.h>
#include <unistd.h>
#include <errno.h>

#include <config.h>
#include <_str_functions_internal.h>
#include <odp_posix_extensions.h>
#include <odp_config_internal.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp_align_internal.h>

#include <pci_internal.h>

#define MAX_PCI_DEVICES 16

typedef union {
	pci_dev_t d;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(pci_dev_t))];
} pci_dev_item_t;

typedef struct pci_admin_data {
	pci_dev_t *avail;
	pci_dev_t *used;
	odp_shm_t shm;
} pci_admin_data_t;

typedef union {
	struct pci_admin_data d;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pci_admin_data))];
} pci_admin_data_u;

static pci_admin_data_u *admin_data;

static int alloc_admin_data(void)
{
	uint64_t size;
	pci_dev_item_t *item;
	odp_shm_t shm;

	size = sizeof(pci_admin_data_u) +
		sizeof(pci_dev_item_t) * MAX_PCI_DEVICES;

	shm = odp_shm_reserve(PCI_ENUMED_DEV, size, 0, ODP_SHM_SINGLE_VA);
	if (shm == ODP_SHM_INVALID)
		return -1;

	admin_data = odp_shm_addr(shm);
	if (!admin_data)
		return -1;

	item = (pci_dev_item_t *)((uint8_t *)admin_data +
				  sizeof(pci_admin_data_u));
	admin_data->d.avail = (pci_dev_t *)item;
	admin_data->d.used = NULL;
	admin_data->d.shm = shm;

	for (int i = 0; i < MAX_PCI_DEVICES - 1; ++i)
		item[i].d.next = (pci_dev_t *)&item[i + 1];

	item[MAX_PCI_DEVICES - 1].d.next = NULL;

	return 0;
}

static pci_dev_t *alloc_dev(void)
{
	pci_dev_t *dev;

	dev = admin_data->d.avail;
	if (admin_data->d.avail == NULL)
		return NULL;

	admin_data->d.avail = dev->next;
	dev->next = NULL;

	return dev;
}

static void free_dev(pci_dev_t *dev)
{
	if (dev == NULL)
		return;

	if (admin_data->d.used == NULL)
		goto do_exit;

	if (dev == admin_data->d.used) {
		admin_data->d.used = dev->next;
	} else {
		pci_dev_t *prev = admin_data->d.used;
		pci_dev_t *curr = prev->next;

		while (curr != NULL && curr != dev) {
			curr = curr->next;
			prev = prev->next;
		}
		if (curr == dev)
			prev->next = curr->next;
	}

do_exit:
	dev->next = admin_data->d.avail;
	admin_data->d.avail = dev;
}

/*
 * PCI probing:
 * these functions are used to simulate a PCI probe by parsing information
 * in sysfs.
 */

#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"

const char *pci_get_sysfs_path(void)
{
        const char *path = NULL;

        path = getenv("SYSFS_PCI_DEVICES");
        if (path == NULL)
                return SYSFS_PCI_DEVICES;

        return path;
}

int pci_read_config(pci_dev_t *dev, void *buf, size_t len, off_t offset)
{
	if (dev == NULL || dev->user_access_ops == NULL) {
		ODP_DBG("Called pci_read_config with NULL device or dev->user_access_ops.\n");
		return -1;
	}

	if (dev->user_access_ops->read_config == NULL) {
		ODP_DBG("Called pci_read_config with read_config==NULL.\n");
		return -1;
	}

	return dev->user_access_ops->read_config(dev, buf, len, offset);
}

/*
 * parse a sysfs (or other) file containing one integer value
 * return this positive integer, or -1 on error
 */
static int pci_parse_sysfs_value(const char *filename, unsigned long *val)
{
	FILE *f;
	char buf[BUFSIZ];
	char *end = NULL;

	f = fopen(filename, "r");
	if (f == NULL) {
		ODP_ERR("cannot open sysfs file %s\n", filename);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f) == NULL) {
		ODP_ERR("cannot read sysfs file %s\n", filename);
		fclose(f);
		return -1;
	}
	*val = strtoul(buf, &end, 0);
	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) {
		ODP_ERR("cannot parse sysfs value %s\n", filename);
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/*
 * given a path (filename) such as "/sys/bus/pci/devices/0000:23:00.0/driver",
 * returns the driver name (a string) in dri_name.
 * The returned name is simply what the "driver" links points to.
 * returns 0 on success, -1 on failure.
 */
static int pci_get_kernel_driver_by_path(const char *filename, char *dri_name)
{
	char path[PATH_MAX];
	char *name;

	if (!filename || !dri_name)
		return -1;

	if (realpath(filename, path) == NULL)
		return -1;

	name = strrchr(path, '/');
	if (name) {
		strncpy(dri_name, name + 1, strlen(name + 1) + 1);
		return 0;
	}

	return -1;
}

/*
 * parse one line of the "resource" sysfs file (note that the 'line'
 * string is modified)
 * Sets phys_addr, end_addr, and flags as read from the given line.
 * returns 0 on success, -1 on failure.
 */
static int pci_parse_one_sysfs_resource(char *line, size_t len,
					uint64_t *phys_addr,
					uint64_t *end_addr, uint64_t *flags)
{
	union pci_resource_info {
		struct {
			char *phys_addr;
			char *end_addr;
			char *flags;
		};
		char *ptrs[PCI_RESOURCE_FMT_NVAL];
	} res_info;

	if (_odp_strsplit(line, len, res_info.ptrs, 3, ' ') != 3) {
		ODP_ERR("bad PCI resource format!\n");
		return -1;
	}
	errno = 0;
	*phys_addr = strtoull(res_info.phys_addr, NULL, 16);
	*end_addr = strtoull(res_info.end_addr, NULL, 16);
	*flags = strtoull(res_info.flags, NULL, 16);
	if (errno != 0) {
		ODP_ERR("bad PCI resource format!\n");
		return -1;
	}

	return 0;
}

/*
 * parse the "resource" sysfs file
 * filename is expected to be something like:
 * /sys/bus/pci/devices/0000:23:00.0/resource
 * returns 0 on success, -1 on failure.
 */
static int pci_parse_sysfs_resource(const char *filename, pci_dev_t *dev)
{
	FILE *f;
	char buf[BUFSIZ];
	int i;
	uint64_t phys_addr, end_addr, flags;

	f = fopen(filename, "r");
	if (f == NULL) {
		ODP_ERR("Cannot open sysfs resource!\n");
		return -1;
	}

	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if (fgets(buf, sizeof(buf), f) == NULL) {
			ODP_ERR("cannot read resource\n");
			goto error;
		}
		if (pci_parse_one_sysfs_resource(buf, sizeof(buf), &phys_addr,
						 &end_addr, &flags) < 0)
			goto error;

		if (flags & IORESOURCE_MEM) {
			dev->bar[i].phys_addr = phys_addr;
			dev->bar[i].len = end_addr - phys_addr + 1;
			/* not mapped for now */
			dev->bar[i].addr = NULL;
		}
	}
	fclose(f);
	return 0;

error:
	fclose(f);
	return -1;
}

/*
 * compare two PCI device addresses.
 * Returns:
 *	0 on equal PCI address.
 *	Positive on addr is greater than addr2.
 *	Negative on addr is less than addr2, or error.
 */
static inline int pci_address_compare(const struct pci_addr_t *addr,
				      const struct pci_addr_t *addr2)
{
	uint64_t dev_addr, dev_addr2;

	if ((addr == NULL) || (addr2 == NULL))
		return -1;

	dev_addr = (addr->domain << 24) | (addr->bus << 16) |
				(addr->devid << 8) | addr->function;
	dev_addr2 = (addr2->domain << 24) | (addr2->bus << 16) |
				(addr2->devid << 8) | addr2->function;

	if (dev_addr > dev_addr2)
		return 1;
	else if (dev_addr < dev_addr2)
		return -1;
	else
		return 0;
}

/*
 * split up a pci address into its constituent parts.
 */
static int parse_pci_addr_format(const char *buf, uint16_t *domain,
				 uint8_t *bus, uint8_t *devid,
				 uint8_t *function)
{
	int bufsize;
	char *buf_copy;
	union splitaddr {
		struct {
			char *domain;
			char *bus;
			char *devid;
			char *function;
		};
		char *str[PCI_FMT_NVAL]; /* last separator is "." not ":" */
	} splitaddr;

	/* copy original address to avoid damaging it with _odp_strsplit: */
	bufsize = strlen(buf) + 1;
	buf_copy = malloc(bufsize);
	strcpy(buf_copy, buf);

	if (buf_copy == NULL)
		return -1;

	/* first split on ':' */
	if (_odp_strsplit(buf_copy, bufsize, splitaddr.str, PCI_FMT_NVAL, ':')
			!= PCI_FMT_NVAL - 1)
		goto error;
	/* final split is on '.' between devid and function */
	splitaddr.function = strchr(splitaddr.devid, '.');
	if (splitaddr.function == NULL)
		goto error;
	*splitaddr.function++ = '\0';

	/* now convert to int values */
	errno = 0;
	*domain = (uint16_t)strtoul(splitaddr.domain, NULL, 16);
	*bus = (uint8_t)strtoul(splitaddr.bus, NULL, 16);
	*devid = (uint8_t)strtoul(splitaddr.devid, NULL, 16);
	*function = (uint8_t)strtoul(splitaddr.function, NULL, 10);
	if (errno != 0)
		goto error;

	free(buf_copy); /* free the copy made with strdup */
	return 0;
error:
	free(buf_copy);
	return -1;
}

/*
 * Scan one pci sysfs entry, and fill the device list from it.
 * dirname should point to a sysfs pci dev entry, e.g.
 * /sys/bus/pci/devices/0000:23:00.0
 * the given device (dev) is filled with the data from the sysfs entry.
 * returns 0 on success, -1 on failure.
 */
static pci_dev_t *pci_scan_one(const char *dirname, uint16_t domain,
			       uint8_t bus, uint8_t devid, uint8_t function,
			       pci_dev_t **devlist)
{
	char filename[PATH_MAX];
	unsigned long tmp;
	char driver[PATH_MAX];
	int ret;
	pci_dev_t *dev;
	pci_dev_t *dev2;

	dev = alloc_dev();
	if (dev == NULL)
		return NULL;

	memset(dev, 0, sizeof(*dev));
	dev->addr.domain = domain;
	dev->addr.bus = bus;
	dev->addr.devid = devid;
	dev->addr.function = function;

	/* get vendor id */
	snprintf(filename, sizeof(filename), "%s/vendor", dirname);
	if (pci_parse_sysfs_value(filename, &tmp) < 0) {
		free_dev(dev);
		return NULL;
	}
	dev->id.vendor_id = (uint16_t)tmp;

	/* get device id */
	snprintf(filename, sizeof(filename), "%s/device", dirname);
	if (pci_parse_sysfs_value(filename, &tmp) < 0) {
		free_dev(dev);
		return NULL;
	}
	dev->id.device_id = (uint16_t)tmp;

	/* get subsystem_vendor id */
	snprintf(filename, sizeof(filename), "%s/subsystem_vendor",
		 dirname);
	if (pci_parse_sysfs_value(filename, &tmp) < 0) {
		free_dev(dev);
		return NULL;
	}
	dev->id.subsystem_vendor_id = (uint16_t)tmp;

	/* get subsystem_device id */
	snprintf(filename, sizeof(filename), "%s/subsystem_device",
		 dirname);
	if (pci_parse_sysfs_value(filename, &tmp) < 0) {
		free_dev(dev);
		return NULL;
	}
	dev->id.subsystem_device_id = (uint16_t)tmp;

	/* get class_id */
	snprintf(filename, sizeof(filename), "%s/class",
		 dirname);
	if (pci_parse_sysfs_value(filename, &tmp) < 0) {
		free_dev(dev);
		return NULL;
	}
	/* the least 24 bits are valid: class, subclass, program interface */
	dev->id.class_id = (uint32_t)tmp & PCI_CLASS_ANY_ID;

	/* get max_vfs */
	dev->max_vfs = 0;
	snprintf(filename, sizeof(filename), "%s/max_vfs", dirname);
	if (!access(filename, F_OK) &&
	    pci_parse_sysfs_value(filename, &tmp) == 0)
		dev->max_vfs = (uint16_t)tmp;
	else {
		snprintf(filename, sizeof(filename),
			 "%s/sriov_numvfs", dirname);
		if (!access(filename, F_OK) &&
		    pci_parse_sysfs_value(filename, &tmp) == 0)
			dev->max_vfs = (uint16_t)tmp;
	}

	/* parse resources */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	if (pci_parse_sysfs_resource(filename, dev) < 0) {
		ODP_ERR("cannot parse resource\n");
		free_dev(dev);
		return NULL;
	}

	/* parse driver */
	snprintf(filename, sizeof(filename), "%s/driver", dirname);
	ret = pci_get_kernel_driver_by_path(filename, driver);
	if (ret < 0) {
		ODP_ERR("Fail to get kernel driver\n");
		free_dev(dev);
		return NULL;
	}
	if (!ret) {
		if (!strcmp(driver, "vfio-pci"))
			dev->kdrv = PCI_KDRV_VFIO;
		else if (!strcmp(driver, "igb_uio"))
			dev->kdrv = PCI_KDRV_IGB_UIO;
		else if (!strcmp(driver, "uio_pci_generic"))
			dev->kdrv = PCI_KDRV_UIO_GENERIC;
		else
			dev->kdrv = PCI_KDRV_UNKNOWN;
	} else {
		dev->kdrv = PCI_KDRV_NONE;
	}

	/* device is valid, add in list (sorted): */
	if (!(*devlist)) {
		*devlist = dev;
		dev->next = NULL;
		return dev;
	}
	if (pci_address_compare(&dev->addr, &(*devlist)->addr) < 0) {
		dev->next = *devlist;
		*devlist = dev;
		return dev;
	}
	for (dev2 = *devlist; dev2->next; dev2 = dev2->next) {
		ret = pci_address_compare(&dev->addr,
					  &dev2->next->addr);
		if (ret > 0)
			continue;

		if (ret < 0) {
			dev->next = dev2->next;
			dev2->next = dev;
		} else { /* already registered */
			dev2->kdrv = dev->kdrv;
			dev2->max_vfs = dev->max_vfs;
			memmove(dev2->bar, dev->bar, sizeof(dev->bar));
			free_dev(dev);
		}
		return dev;
	}
	dev2->next = dev;
	dev->next = NULL;
	return dev;
}

#if 0 /* FIXME */

/*
 * Scan the content of the PCI bus, and fill the PCI enumerated device list
 */
static int pci_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];
	uint16_t domain;
	uint8_t bus, devid, function;

	dir = opendir(pci_get_sysfs_path());

	if (dir == NULL) {
		ODP_DBG("opendir failed: %s\n", strerror(errno));
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		if (parse_pci_addr_format(e->d_name, &domain,
					  &bus, &devid, &function) != 0)
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
			 PCI_SYSFS_DEVICES_ROOT, e->d_name);
		pci_scan_one(dirname, domain, bus, devid, function,
			     &(admin_data->d.used));
	}
	closedir(dir);

	return 0;
}

#endif

/*
 * output a printout of the scanned PCI devices (debug purpose)
 */
static int pci_dump_scanned(void)
{
	pci_dev_t *dev;
	const char *driver;

	if (admin_data == NULL)
		return -1;

	ODP_DBG("list of scanned PCI devices:\n");
	for (dev = admin_data->d.used; dev != NULL; dev = dev->next) {
		switch (dev->kdrv) {
			case PCI_KDRV_VFIO:
				driver = "vfio";
				break;
			case PCI_KDRV_IGB_UIO:
				driver = "igb_uio";
				break;
			case PCI_KDRV_UIO_GENERIC:
				driver = "uio_pci_generic";
				break;
			default:
				driver = "unknown";
		}
		ODP_PRINT("PCI DEVICE:"
			  "%04" PRIx16 ":"
			  "%02" PRIx8 ":"
			  "%02" PRIx8 ":"
			  "%02" PRIx8 ": "
			  "vendor:%04" PRIx16 ", "
			  "device:%04" PRIx16 ", "
			  "class:%04" PRIx16 ", "
			  "driver: %s\n",
			  dev->addr.domain,
			  dev->addr.bus,
			  dev->addr.devid,
			  dev->addr.function,
			  dev->id.vendor_id,
			  dev->id.device_id,
			  dev->id.class_id,
			  driver);
		for (int i = 0; i < PCI_MAX_RESOURCE; i++) {
			if (dev->bar[i].phys_addr == 0)
				continue;
			ODP_PRINT("\tBAR_%d: phys_addr: %" PRIx64 " -> "
				  "%p, %" PRIx64 " bytes\n",
				  i, dev->bar[i].phys_addr,
				  dev->bar[i].addr,
				  dev->bar[i].len);
		}
	}

	return 0;
}

int _odp_pci_init_global(void)
{
	if (alloc_admin_data())
		return -1;

	ODP_DBG("PCI interface initialized\n");

	return 0;
}

int _odp_pci_term_global(void)
{
	/* free the enumarated PCI device list (if any) */
	if (admin_data)
		odp_shm_free(admin_data->d.shm);

	return 0;
}

int pci_ioport_map(pci_dev_t *dev , int idx, pci_ioport_t *p)
{
	int ret = -1;

	if (dev == NULL || dev->user_access_ops == NULL) {
		ODP_DBG("Called pci_unmap_device with NULL device or "
			"dev->user_access_ops.\n");
		return -1;
	}

	if (dev->user_access_ops->ioport_map == NULL) {
		ODP_DBG("Called pci_unmap_device with ioport_map==NULL.\n");
		return -1;
	}

	ret = dev->user_access_ops->ioport_map(dev, idx, p);

	if (!ret)
		p->dev = dev;

	return ret;
}

int pci_ioport_unmap(pci_dev_t *dev, pci_ioport_t *p )
{
	int ret = -1;

	if (dev == NULL || dev->user_access_ops == NULL) {
		ODP_DBG("Called pci_unmap_device with NULL device or "
			"dev->user_access_ops.\n");
		return -1;
	}

	if (dev->user_access_ops->ioport_unmap == NULL) {
		ODP_DBG("Called pci_unmap_device with "
			"pci_ioport_unmap==NULL.\n");
		return -1;
	}

	ret = dev->user_access_ops->ioport_unmap(dev, p);

	return ret;
}

void pci_ioport_read(pci_dev_t *dev, pci_ioport_t *p, void *data, size_t len,
		     off_t offset)
{
	if (dev == NULL || dev->user_access_ops == NULL) {
		ODP_DBG("Called pci_unmap_device with NULL device or "
			"dev->user_access_ops.\n");
		return ;
	}

	if (dev->user_access_ops->ioport_read == NULL) {
		ODP_DBG("Called pci_unmap_device with ioport_read==NULL.\n");
		return ;
	}

	dev->user_access_ops->ioport_read(dev, p, data, len, offset);
}

void pci_ioport_write(pci_dev_t *dev, pci_ioport_t *p ODP_UNUSED,
		      const void *data ODP_UNUSED, size_t len ODP_UNUSED,
		      off_t offset ODP_UNUSED)
{
	if (dev == NULL || dev->user_access_ops == NULL) {
		ODP_DBG("Called pci_unmap_device with NULL device or "
			"dev->user_access_ops.\n");
		return ;
	}

	if (dev->user_access_ops->ioport_write == NULL) {
		ODP_DBG("Called pci_unmap_device with ioport_write==NULL.\n");
		return ;
	}

	dev->user_access_ops->ioport_write(dev, p, data, len, offset);
}

/* pci drivers use this function to open a PCI device from the /sys/bus filesystem
 * It returns a pci_dev_t struct with several fields filled in. The driver can
 * then decide if it can handle the device or not based on device ID.
 * On error it returns NULL.
 */
pci_dev_t *pci_open_device(const char *dev)
{
	uint16_t domain;
	uint8_t bus, device, function;
	char dirname[PATH_MAX];
	pci_dev_t *pci_dev;

	if (admin_data == NULL || admin_data->d.avail == NULL)
		return NULL;

	if (parse_pci_addr_format(dev, &domain, &bus, &device, &function)) {
		ODP_ERR("Error in device: %s\n", dev);
		return NULL;
	}

	snprintf(dirname, sizeof(dirname), "%s/%s",
		 pci_get_sysfs_path(), dev);
	pci_dev = pci_scan_one(dirname, domain, bus, device, function,
			       &admin_data->d.used);
	if (pci_dev == NULL)
		return NULL;

	if (pci_dump_scanned())
		ODP_ERR("Could not dump\n");

	return pci_dev;
}

int pci_close_device(pci_dev_t *dev)
{
	if (dev->user_access_ops != NULL)
		dev->user_access_ops->unmap_resource(dev);

	free_dev(dev);

	return 0;
}
