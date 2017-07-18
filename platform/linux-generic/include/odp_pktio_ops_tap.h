/* Copyright (c) 2015, Ilya Maximets <i.maximets@samsung.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_OPS_TAP_H
#define ODP_PACKET_OPS_TAP_H

#include <odp/api/pool.h>

typedef struct {
	int fd;				/**< file descriptor for tap interface*/
	int skfd;			/**< socket descriptor */
	uint32_t mtu;			/**< cached mtu */
	unsigned char if_mac[ETH_ALEN];	/**< MAC address of pktio side (not a
					     MAC address of kernel interface)*/
	odp_pool_t pool;		/**< pool to alloc packets from */
} pktio_ops_tap_data_t;

#endif
