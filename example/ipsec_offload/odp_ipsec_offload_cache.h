/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_IPSEC_CACHE_H_
#define ODP_IPSEC_CACHE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp.h>
#include <odp/helper/ipsec.h>

#include <odp_ipsec_offload_misc.h>
#include <odp_ipsec_offload_sa_db.h>

/**
 * IPsec cache data base entry
 */
typedef struct ipsec_cache_entry_s {
	struct ipsec_cache_entry_s	*next;		/**< Next entry on list */
	uint32_t			src_ip;		/**< Source v4 address */
	uint32_t			dst_ip;		/**< Destination v4 address */
	odp_ipsec_sa_t			sa;		/**< IPSec sa handle */
} ipsec_cache_entry_t;

/**
 * IPsec cache data base global structure
 */
typedef struct ipsec_cache_s {
	uint32_t             index;       /**< Index of next available entry */
	ipsec_cache_entry_t *in_list;     /**< List of active input entries */
	ipsec_cache_entry_t *out_list;    /**< List of active output entries */
	ipsec_cache_entry_t  array[MAX_DB]; /**< Entry storage */
} ipsec_cache_t;

/** Global pointer to ipsec_cache db */
extern ipsec_cache_t *ipsec_cache;

/** Initialize IPsec cache */
void init_ipsec_cache(void);

/**
 * Create an entry in the IPsec cache
 *
 * @param cipher_sa   Cipher SA DB entry pointer
 * @param auth_sa     Auth SA DB entry pointer
 * @param tun         Tunnel DB entry pointer
 * @param in          Direction (input versus output)
 * @param completionq Completion queue
 *
 * @return 0 if successful else -1
 */
int create_ipsec_cache_entry(sa_db_entry_t *cipher_sa,
			     sa_db_entry_t *auth_sa,
			     tun_db_entry_t *tun,
			     odp_bool_t in,
			     odp_queue_t completionq);

/**
 * Find a matching IPsec cache entry for output packet
 *
 * @param src_ip    Source IPv4 address
 * @param dst_ip    Destination IPv4 address
 *
 * @return pointer to IPsec cache entry else NULL
 */
ipsec_cache_entry_t *find_ipsec_cache_entry_out(uint32_t src_ip,
						uint32_t dst_ip);

#ifdef __cplusplus
}
#endif

#endif
