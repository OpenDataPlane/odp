/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ODP_FRAGREASS_PP_FRAG_H_
#define ODP_FRAGREASS_PP_FRAG_H_

#include <odp/helper/ip.h>

#define MTU 1480 /**< IPv4 payload MTU */

ODP_STATIC_ASSERT(!(MTU % 8), "ODPFRAG_MTU__SIZE_ERROR");

/**
 * Break apart a larger-than-MTU packet into smaller IPv4 fragments
 *
 * @param      orig_packet The larger-than-MTU packet to fragment
 * @param[out] out	   The packet buffer to write fragments out to
 * @param[out] out_len	   The number of fragments produced
 *
 * @return 0 on success, -1 otherwise
 */
int fragment_ipv4_packet(odp_packet_t orig_packet, odp_packet_t *out,
			 int *out_len);

#endif
