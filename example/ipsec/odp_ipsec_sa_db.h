/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_IPSEC_SA_DB_H_
#define ODP_IPSEC_SA_DB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_ipsec_misc.h>

/**
 * Security Association (SA) data base entry
 */
typedef struct sa_db_entry_s {
	struct sa_db_entry_s *next;      /**< Next entry on list */
	uint32_t              src_ip;    /**< Source IPv4 address */
	uint32_t              dst_ip;    /**< Desitnation IPv4 address */
	uint32_t              spi;       /**< Security Parameter Index */
	ipsec_alg_t           alg;       /**< Cipher/auth algorithm */
	ipsec_key_t           key;       /**< Cipher/auth key */
	uint32_t              block_len; /**< Cipher block length */
	uint32_t              iv_len;    /**< Initialization Vector length */
	uint32_t              icv_len;   /**< Integrity Check Value length */
} sa_db_entry_t;

/**
 * Security Association (SA) data base global structure
 */
typedef struct sa_db_s {
	uint32_t         index;          /**< Index of next available entry */
	sa_db_entry_t   *list;           /**< List of active entries */
	sa_db_entry_t    array[MAX_DB];  /**< Entry storage */
} sa_db_t;

/** Initialize SA database global control structure */
void init_sa_db(void);

/**
 * Create an SA DB entry
 *
 * String is of the format "SrcIP:DstIP:Alg:SPI:Key"
 *
 * @param input  Pointer to string describing SA
 * @param cipher TRUE if cipher else FALSE for auth
 *
 * @return 0 if successful else -1
 */
int create_sa_db_entry(char *input, odp_bool_t cipher);
/**
 * Display the SA DB
 */
void dump_sa_db(void);

/**
 * Find a matching SA DB entry
 *
 * @param src    Pointer to source subnet/range
 * @param dst    Pointer to destination subnet/range
 * @param cipher TRUE if cipher else FALSE for auth
 *
 * @return pointer to SA DB entry else NULL
 */
sa_db_entry_t *find_sa_db_entry(ip_addr_range_t *src,
				ip_addr_range_t *dst,
				odp_bool_t cipher);

#ifdef __cplusplus
}
#endif

#endif
