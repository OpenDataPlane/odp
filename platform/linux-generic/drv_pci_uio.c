#/* Copyright (c) 2016, Linaro Limited
* All rights reserved.
*
* SPDX-License-Identifier:     BSD-3-Clause
*/

/* Many of this functions have been inspired by their dpdk counterpart,
 * hence the following copyright and license:
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 */

/**
 * @file
 * PCI interface for UIO drivers
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>

#if !defined (ARM_ARCHITECTURE)
#include <sys/io.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <linux/limits.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/pci_regs.h>
#include <_str_functions_internal.h>

#include <odp_posix_extensions.h>
#include <odp_config_internal.h>
#include <odp_internal.h>
#include <odp/drv/shm.h>
#include <odp_debug_internal.h>

#include <drv_pci_internal.h>

typedef struct user_access_context_t {
	int uio_num; /**< device number assigned by UIO: /dev/uioX */
	int uio_fd; /**< file descriptor for /dev/uioX */
	int uio_cfg_fd; /**< file descriptor for accessing device's config space */
	int nb_maps;
	struct pci_map maps[PCI_MAX_RESOURCE];
	char path[PATH_MAX];
} user_access_context_t;

void *pci_map_addr = NULL;


/* map a particular resource from a file */
static void *pci_uio_map_resource(void *requested_addr, int fd, off_t offset,
				  size_t size, int additional_flags)
{
	void *mapaddr;

	/* Map the PCI memory resource of device */
	mapaddr = mmap(requested_addr, size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | additional_flags, fd, offset);
	if (mapaddr == MAP_FAILED) {
		ODP_ERR("%s(): cannot mmap(%d, %p, 0x%lx, 0x%lx): %s (%p)\n",
			__func__, fd, requested_addr,
			(unsigned long)size, (unsigned long)offset,
			strerror(errno), mapaddr);
	} else {
		ODP_ERR("  PCI memory mapped at %p\n", mapaddr);
	}

	return mapaddr;
}

static int pci_uio_set_bus_master(pci_dev_t *dev)
{
	uint16_t reg;
	int ret;
	int cfg_fd = dev->user_access_context->uio_cfg_fd;

	ret = pread(cfg_fd, &reg, sizeof(reg), PCI_COMMAND);
	if (ret != sizeof(reg)) {
		ODP_ERR("Cannot read command from PCI config space!\n");
		return -1;
	}

	/* return if bus mastering is already on */
	if (reg & PCI_COMMAND_MASTER)
		return 0;

	reg |= PCI_COMMAND_MASTER;

	ret = pwrite(cfg_fd, &reg, sizeof(reg), PCI_COMMAND);
	if (ret != sizeof(reg)) {
		ODP_ERR("Cannot write command to PCI config space!\n");
		return -1;
	}

	return 0;
}

/*
 * Return the uioX char device used for a pci device. On success, return
 * the UIO number and fill dstbuf string with the path of the device in
 * sysfs. On error, return a negative value. In this case dstbuf is
 * invalid.
 */
static int pci_uio_get_uio_dev(pci_dev_t *dev, char *dstbuf,
			       unsigned int buflen)
{
	struct pci_addr_t *loc = &dev->addr;
	unsigned int uio_num;
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];

	/* depending on kernel version, uio can be located in uio/uioX
	 * or uio:uioX */

	snprintf(dirname, sizeof(dirname),
		 "%s/" PCI_PRI_FMT "/uio", pci_get_sysfs_path(),
		 loc->domain, loc->bus, loc->devid, loc->function);

	dir = opendir(dirname);
	if (dir == NULL) {
		/* retry with the parent directory */
		snprintf(dirname, sizeof(dirname),
			 "%s/" PCI_PRI_FMT, pci_get_sysfs_path(),
			 loc->domain, loc->bus, loc->devid, loc->function);
		dir = opendir(dirname);

		if (dir == NULL) {
			ODP_ERR("Cannot opendir %s\n", dirname);
			return -1;
		}
	}

	/* take the first file starting with "uio" */
	while ((e = readdir(dir)) != NULL) {
		/* format could be uio%d ...*/
		int shortprefix_len = sizeof("uio") - 1;
		/* ... or uio:uio%d */
		int longprefix_len = sizeof("uio:uio") - 1;
		char *endptr;

		if (strncmp(e->d_name, "uio", 3) != 0)
			continue;

		/* first try uio%d */
		errno = 0;
		uio_num = strtoull(e->d_name + shortprefix_len, &endptr, 10);
		if (errno == 0 && endptr != (e->d_name + shortprefix_len)) {
			snprintf(dstbuf, buflen, "%s/uio%u", dirname, uio_num);
			break;
		}

		/* then try uio:uio%d */
		errno = 0;
		uio_num = strtoull(e->d_name + longprefix_len, &endptr, 10);
		if (errno == 0 && endptr != (e->d_name + longprefix_len)) {
			snprintf(dstbuf, buflen, "%s/uio:uio%u", dirname,
				 uio_num);
			break;
		}
	}
	closedir(dir);

	/* No uio resource found */
	if (e == NULL)
		return -1;

	return uio_num;
}

static void pci_uio_free_context(struct pci_dev_t *dev)
{
	user_access_context_t *ctx = dev->user_access_context;

	if (ctx->uio_cfg_fd >= 0) {
		close(ctx->uio_cfg_fd);
	}
	if (ctx->uio_fd >= 0) {
		close(ctx->uio_fd);
	}

	dev->user_access_context = NULL;
	free(ctx);
}

static int pci_uio_prepare_context(pci_dev_t *dev)
{
	char dirname[PATH_MAX];
	char cfgname[PATH_MAX];
	int uio_num;
	struct pci_addr_t *loc;
	user_access_context_t *ctx;

	ctx = malloc(sizeof(user_access_context_t));
	if (ctx == NULL)
		return -1;

	memset(ctx, 0, sizeof(user_access_context_t));

	loc = &dev->addr;

	/* find uio resource */
	uio_num = pci_uio_get_uio_dev(dev, dirname, sizeof(dirname));
	if (uio_num < 0) {
		ODP_ERR("  "PCI_PRI_FMT" not managed by UIO driver, "
			"skipping\n", loc->domain, loc->bus, loc->devid,
			loc->function);
		return 1;
	}

	ctx->uio_num = uio_num;
	snprintf(ctx->path, sizeof(dev->user_access_context->path),
		 "/dev/uio%u", uio_num);
	dev->user_access_context = ctx;

	ctx->uio_fd = open(ctx->path, O_RDWR);
	if (ctx->uio_fd < 0) {
		ODP_ERR("Cannot open %s: %s\n", ctx->path, strerror(errno));
		goto error;
	}

	snprintf(cfgname, sizeof(cfgname),
		 "/sys/class/uio/uio%u/device/config", uio_num);
	ctx->uio_cfg_fd = open(cfgname, O_RDWR);
	if (ctx->uio_cfg_fd < 0) {
		ODP_ERR("Cannot open %s: %s\n", cfgname, strerror(errno));
		goto error;
	}

	/* set bus master that is not done by uio_pci_generic */
	if (pci_uio_set_bus_master(dev)) {
		ODP_ERR("Cannot set up bus mastering!\n");
		goto error;
	}

	return 0;

error:
	pci_uio_free_context(dev);
	return -1;
}


static int pci_uio_map_resource_by_index(pci_dev_t *dev, int res_idx,
					 int map_idx)
{
	int fd;
	char devname[PATH_MAX];
	void *mapaddr;
	struct pci_addr_t *loc;
	user_access_context_t *ctx;

	loc = &dev->addr;
	ctx = dev->user_access_context;

	/* update devname for mmap  */
	snprintf(devname, sizeof(devname),
		 "%s/" PCI_PRI_FMT "/resource%d",
		 pci_get_sysfs_path(),
		 loc->domain, loc->bus, loc->devid,
		 loc->function, res_idx);

	/* allocate memory to keep path */
	ctx->maps[map_idx].path = malloc(strlen(devname) + 1);
	if (ctx->maps[map_idx].path == NULL) {
		ODP_ERR("Cannot allocate memory for path: %s\n",
			strerror(errno));
		return -ENOMEM;
	}

	/*
	* open resource file, to mmap it
	*/
	fd = open(devname, O_RDWR);
	if (fd < 0) {
		ODP_ERR("Cannot open %s: %s\n",
			devname, strerror(errno));
		goto error;
	}

	/* try mapping somewhere close to the end of hugepages */
	//if (pci_map_addr == NULL) pci_map_addr = pci_find_max_end_va();

	mapaddr = pci_uio_map_resource(pci_map_addr, fd, 0,
				       (size_t)dev->bar[res_idx].len, 0);
	close(fd);
	if (mapaddr == MAP_FAILED)
		goto error;

	//pci_map_addr = (void*)((uintptr_t)mapaddr + (size_t)dev->bar[res_idx].len);

	ctx->maps[map_idx].phaddr = dev->bar[res_idx].phys_addr;
	ctx->maps[map_idx].size = dev->bar[res_idx].len;
	ctx->maps[map_idx].addr = mapaddr;
	ctx->maps[map_idx].offset = 0;
	strcpy(ctx->maps[map_idx].path, devname);
	dev->bar[res_idx].addr = mapaddr;

	return 0;

error:
	free(ctx->maps[map_idx].path);
	ctx->maps[map_idx].path = NULL;
	return -1;
}


static int pci_uio_map_resources(pci_dev_t *dev)
{
	int map_idx = 0;

	/* don't call before probing*/
	if (dev->user_access_context == NULL)
		return -1;

	/* we've been here before, no need to try again */
	if (dev->user_access_context->nb_maps != 0)
		return 0;

	/* Map all BARs */
	for (int i = 0; i != PCI_MAX_RESOURCE; i++) {
		uint64_t phaddr = dev->bar[i].phys_addr;

		/* skip empty BAR */
		if (phaddr == 0)
			continue;

		if (pci_uio_map_resource_by_index(dev, i, map_idx))
			goto error;

		map_idx++;
	}

	dev->user_access_context->nb_maps = map_idx;

	return 0;

error:
#ifdef ACTIVATED
	for (i = 0; i < map_idx; i++) {
		pci_unmap_resource(uio_res->maps[i].addr,
				   (size_t)uio_res->maps[i].size);
		rte_free(uio_res->maps[i].path);
	}
	pci_uio_free_resource(dev, uio_res);
	dev->user_access_context->nb_maps = 0;
#endif
	return -1;
}

static int pci_uio_unmap_resources(pci_dev_t *dev)
{
	if (dev == NULL)
		return -1;
#ifdef ACTIVATED
	/* find an entry for the device */
	uio_res = pci_uio_find_resource(dev);
	if (uio_res == NULL)
		return;

	/* unmap all resources */
	pci_uio_unmap(uio_res);

	/* free uio resource */
	free(uio_res);

	/* close fd if in primary process */
	if (dev->user_access_context->uio_cfg_fd >= 0) {
		close(dev->user_access_context->uio_cfg_fd);
	}
#endif
	return 0;
}

static int pci_uio_read_config(pci_dev_t *dev, void *buf, size_t len,
			       off_t offset)
{
	return pread(dev->user_access_context->uio_cfg_fd, buf, len, offset);
}

static int pci_uio_write_config(pci_dev_t *dev, void *buf, size_t len,
				off_t offset)
{
	return pwrite(dev->user_access_context->uio_cfg_fd, buf, len, offset);
}

#if !defined(ARM_ARCHITECTURE)
static int pci_uio_ioport_map(pci_dev_t* dev, int idx ODP_UNUSED,
			      pci_ioport_t *p)
{
	uint16_t start, end;
	FILE *fp;
	char *line = NULL;
	char pci_id[16];
	int found = 0;
	size_t linesz;

	snprintf(pci_id, sizeof(pci_id), PCI_PRI_FMT,
		dev->addr.domain, dev->addr.bus,
		dev->addr.devid, dev->addr.function);

	fp = fopen("/proc/ioports", "r");
	if (fp == NULL) {
		ODP_ERR("%s(): can't open ioports\n", __func__);
		return -1;
	}

	while (getdelim(&line, &linesz, '\n', fp) > 0) {
		char *ptr = line;
		char *left;
		int n;

		n = strcspn(ptr, ":");
		ptr[n] = 0;
		left = &ptr[n + 1];

		while (*left && isspace(*left))
			left++;

		if (!strncmp(left, pci_id, strlen(pci_id))) {
			found = 1;

			while (*ptr && isspace(*ptr))
				ptr++;

			sscanf(ptr, "%04hx-%04hx", &start, &end);

			break;
		}
	}

	free(line);
	fclose(fp);

	if (!found)
		return -1;

	p->base = start;
	ODP_PRINT("PCI Port IO found start=0x%x\n", start);

	return 0;
}
#else
int pci_uio_ioport_map(struct rte_pci_device *dev, int bar,
		       struct rte_pci_ioport *p)
{
	FILE *f;
	char buf[BUFSIZ];
	char filename[PATH_MAX];
	uint64_t phys_addr, end_addr, flags;
	int fd, i;
	void *addr;

	/* open and read addresses of the corresponding resource in sysfs */
	snprintf(filename, sizeof(filename), "%s/" PCI_PRI_FMT "/resource",
		pci_get_sysfs_path(), dev->addr.domain, dev->addr.bus,
		dev->addr.devid, dev->addr.function);
	f = fopen(filename, "r");
	if (f == NULL) {
		RTE_LOG(ERR, EAL, "Cannot open sysfs resource: %s\n",
			strerror(errno));
		return -1;
	}
	for (i = 0; i < bar + 1; i++) {
		if (fgets(buf, sizeof(buf), f) == NULL) {
			RTE_LOG(ERR, EAL, "Cannot read sysfs resource\n");
			goto error;
		}
	}
	if (pci_parse_one_sysfs_resource(buf, sizeof(buf), &phys_addr,
		&end_addr, &flags) < 0)
		goto error;
	if ((flags & IORESOURCE_IO) == 0) {
		RTE_LOG(ERR, EAL, "BAR %d is not an IO resource\n", bar);
		goto error;
	}
	snprintf(filename, sizeof(filename), "%s/" PCI_PRI_FMT "/resource%d",
		pci_get_sysfs_path(), dev->addr.domain, dev->addr.bus,
		dev->addr.devid, dev->addr.function, bar);

	/* mmap the pci resource */
	fd = open(filename, O_RDWR);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "Cannot open %s: %s\n", filename,
			strerror(errno));
		goto error;
	}
	addr = mmap(NULL, end_addr + 1, PROT_READ | PROT_WRITE,
		MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		RTE_LOG(ERR, EAL, "Cannot mmap IO port resource: %s\n",
			strerror(errno));
		goto error;
	}

	/* strangely, the base address is mmap addr + phys_addr */
	p->base = (uintptr_t)addr + phys_addr;
	p->len = end_addr + 1;
	RTE_LOG(DEBUG, EAL, "PCI Port IO found start=0x%"PRIx64"\n", p->base);
	fclose(f);

	return 0;

error:
	fclose(f);
	return -1;
}
#endif

static int pci_uio_ioport_unmap(pci_dev_t* dev ODP_UNUSED, pci_ioport_t *p ODP_UNUSED)
{
	int ret = -1;
	return ret;
}


static void pci_uio_ioport_read(pci_dev_t* dev ODP_UNUSED, pci_ioport_t *p,
				void *data, size_t len, off_t offset)
{
	uint8_t *d;
	int size;
	uintptr_t reg = p->base + offset;

	for (d = data; len > 0; d += size, reg += size, len -= size) {
		if (len >= 4) {
			size = 4;
#if !defined(ARM_ARCHITECTURE)
			*(uint32_t *)d = inl(reg);
#else
			*(uint32_t *)d = *(volatile uint32_t *)reg;
#endif
		} else if (len >= 2) {
			size = 2;
#if !defined(ARM_ARCHITECTURE)
			*(uint16_t *)d = inw(reg);
#else
			*(uint16_t *)d = *(volatile uint16_t *)reg;
#endif
		} else {
			size = 1;
#if !defined(ARM_ARCHITECTURE)
			*d = inb(reg);
#else
			*d = *(volatile uint8_t *)reg;
#endif
		}
	}
}

static void pci_uio_ioport_write(pci_dev_t* dev ODP_UNUSED, pci_ioport_t *p,
				 const void *data, size_t len, off_t offset)
{
	const uint8_t *s;
	int size;
	uintptr_t reg = p->base + offset;

	for (s = data; len > 0; s += size, reg += size, len -= size) {
		if (len >= 4) {
			size = 4;
#if !defined(ARM_ARCHITECTURE)
			outl_p(*(const uint32_t *)s, reg);
#else
			*(volatile uint32_t *)reg = *(const uint32_t *)s;
#endif
		} else if (len >= 2) {
			size = 2;
#if !defined(ARM_ARCHITECTURE)
			outw_p(*(const uint16_t *)s, reg);
#else
			*(volatile uint16_t *)reg = *(const uint16_t *)s;
#endif
		} else {
			size = 1;
#if !defined(ARM_ARCHITECTURE)
			outb_p(*s, reg);
#else
			*(volatile uint8_t *)reg = *s;
#endif
		}
	}
}

static int pci_uio_probe(struct pci_dev_t *dev)
{
	int ret;

	ret = pci_uio_prepare_context(dev);
	if (ret)
		return ret;

	return 0;
}

const user_access_ops_t uio_access_ops = {
	.probe           = pci_uio_probe,
	.map_resource    = pci_uio_map_resources,
	.unmap_resource  = pci_uio_unmap_resources,
	.read_config     = pci_uio_read_config,
	.write_config    = pci_uio_write_config,
	.ioport_map      = pci_uio_ioport_map,
	.ioport_unmap    = pci_uio_ioport_unmap,
	.ioport_read     = pci_uio_ioport_read,
	.ioport_write    = pci_uio_ioport_write
};
