/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _UAPI__LINUX_NET_MDEV_H
#define _UAPI__LINUX_NET_MDEV_H

#include <linux/types.h>
#include <linux/ioctl.h>

enum net_mdev_types {
	VFIO_NET_MDEV_MMIO,
	VFIO_NET_MDEV_RX_RING,
	VFIO_NET_MDEV_TX_RING,
};

#endif /* _UAPI__LINUX_NET_MDEV_H */
