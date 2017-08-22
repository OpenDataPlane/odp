/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef DRV_PCI_INTERNAL_H_
#define DRV_PCI_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Nb. of values in PCI resource file format. */
#define PCI_RESOURCE_FMT_NVAL 3
/** Nb. of values in PCI device address string. */
#define PCI_FMT_NVAL 4

/* Maximum number of PCI resources (BAR regions). */
#define PCI_MAX_RESOURCE 6

/* IO resource type (flag section of PCI resource file): */
#define IORESOURCE_IO		0x00000100
#define IORESOURCE_MEM		0x00000200

/* Any PCI device identifier (vendor, device, ...) */
#define PCI_CLASS_ANY_ID (0xffffff)

/* name of the shmem area containing the list of enumerated PCI devices: */
#define PCI_ENUMED_DEV "_ODP_PCI_ENUMERATED_DEVICES"

#define PCI_PRI_FMT "%.4" PRIx16 ":%.2" PRIx8 ":%.2" PRIx8 ".%" PRIx8

/* structure describing a PCI address: */
typedef struct pci_addr_t {
	uint16_t domain;		/* Device domain */
	uint8_t bus;			/* Device bus */
	uint8_t devid;			/* Device ID */
	uint8_t function;		/* Device function. */
} pci_addr_t;

/* structure describing an ID for a PCI device: */
typedef struct pci_id_t {
	uint32_t class_id;	      /* Class ID */
	uint16_t vendor_id;	      /* Vendor ID or PCI_ANY_ID. */
	uint16_t device_id;	      /* Device ID or PCI_ANY_ID. */
	uint16_t subsystem_vendor_id; /* Subsystem vendor ID or PCI_ANY_ID. */
	uint16_t subsystem_device_id; /* Subsystem device ID or PCI_ANY_ID. */
} pci_id_t;

/* structure describing a PCI resource (BAR region): */
typedef struct pci_resource_t {
	uint64_t phys_addr;/* Physical address, 0 if no resource. */
	void *addr;	   /* address (virtual, user space) of the BAR region */
	uint64_t len;      /* size of the region, in bytes */
} pci_resource_t;

/* enum telling which kernel driver is currentely bound to the pci device: */
enum pci_kernel_driver {
	PCI_KDRV_UNKNOWN = 0,
	PCI_KDRV_IGB_UIO,
	PCI_KDRV_VFIO,
	PCI_KDRV_UIO_GENERIC,
	PCI_KDRV_NIC_UIO,
	PCI_KDRV_NONE,
};

/**
 * A structure used to access io resources for a pci device.
 * rte_pci_ioport is arch, os, driver specific, and should not be used outside
 * of pci ioport api.
 */
typedef struct pci_ioport_t {
        struct pci_dev_t *dev;
        uint64_t base;
        uint64_t len; /* only filled for memory mapped ports */
} pci_ioport_t;

/**
 * A structure describing a PCI mapping.
 */
struct pci_map {
	void *addr;
	char *path;
	uint64_t offset;
	uint64_t size;
	uint64_t phaddr;
};

/* Opaque type defined by each user access implementation */
typedef struct user_access_context_t user_access_context;

typedef struct user_access_ops_t {
	int(*probe)(struct pci_dev_t *dev);
	int(*map_resource)(struct pci_dev_t *dev);
	int(*unmap_resource)(struct pci_dev_t *dev);
	int(*read_config)(struct pci_dev_t *dev, void *buf, size_t len,
			  off_t offset);
	int(*write_config)(struct pci_dev_t *dev, void *buf, size_t len,
			   off_t offset);
	int(*ioport_map)(struct pci_dev_t *dev, int idx, pci_ioport_t *p);
	int(*ioport_unmap)(struct pci_dev_t *dev, pci_ioport_t *p);
	void(*ioport_read)(struct pci_dev_t *dev, pci_ioport_t *p,
			   void *data, size_t len, off_t offset);
	void(*ioport_write)(struct pci_dev_t *dev, pci_ioport_t *p,
			    const void *data, size_t len, off_t offset);
} user_access_ops_t;

/* structure for PCI device: */
typedef struct pci_dev_t {
	struct pci_dev_t *next;
	pci_addr_t addr;		      /* PCI location. */
	pci_id_t id;			      /* PCI ID. */
	pci_resource_t bar[PCI_MAX_RESOURCE]; /* PCI Resources */
	uint16_t max_vfs;		      /* sriov enable if not zero */
	enum pci_kernel_driver kdrv;	      /* Kernel driver */
	struct user_access_context_t *user_access_context;
	const struct user_access_ops_t *user_access_ops;
} pci_dev_t;

/* path where PCI devices are shown in sysfs: */
const char *pci_get_sysfs_path(void);

struct pci_dev_t *pci_open_device(const char *);
int pci_close_device(pci_dev_t *);

#ifdef __cplusplus
}
#endif

#endif
