/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */


/**
 * @file
 *
 * ODP ICMP header
 */

#ifndef ODPH_ICMP_H_
#define ODPH_ICMP_H_

#include <odp_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odph_protocols
 * @{
 */

/** ICMP header length */
#define ODPH_ICMPHDR_LEN 8

/** ICMP header */
typedef struct ODP_PACKED {
	uint8_t type;		/**< message type */
	uint8_t code;		/**< type sub-code */
	odp_u16sum_t chksum;	/**< checksum of icmp header */
	/** Variant mappings of ICMP fields */
	union {
		/** Fields used for ICMP echo msgs */
		struct {
			odp_u16be_t id;       /**< id */
			odp_u16be_t sequence; /**< sequence */
		} echo;			/**< echo datagram */
		odp_u32be_t gateway;	/**< gateway address */
		/** Fields used for ICMP frag msgs */
		struct {
			odp_u16be_t __unused; /**< @internal */
			odp_u16be_t mtu;  /**< mtu */
		} frag;			/**< path mtu discovery */
	} un;			/**< icmp sub header */
} odph_icmphdr_t;

#define ODPH_ICMP_ECHOREPLY 0 /**< Echo Reply */
#define ODPH_ICMP_ECHO      8 /**< Echo Request */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */
ODP_STATIC_ASSERT(sizeof(odph_icmphdr_t) == ODPH_ICMPHDR_LEN,
		  "ODPH_ICMPHDR_T__SIZE_ERROR");
/** @endcond */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
