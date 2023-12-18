/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_L3FWD_DB_H_
#define _ODP_L3FWD_DB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define OIF_LEN 32
#define MAX_DB  32
#define MAX_STRING  32

/**
 * Max number of flows
 */
#define FWD_MAX_FLOW_COUNT	(1 << 22)

/**
 * Default hash entries in a bucket
 */
#define FWD_DEF_BUCKET_ENTRIES	4

/**
 * IP address range (subnet)
 */
typedef struct ip_addr_range_s {
	uint32_t  addr;     /**< IP address, host endianness */
	uint32_t  depth;    /**< subnet bit width */
} ip_addr_range_t;

/**
 * TCP/UDP flow
 */
typedef struct ODP_ALIGNED_CACHE ipv4_tuple5_s {
	union {
		struct {
			int32_t src_ip;
			int32_t dst_ip;
			int16_t src_port;
			int16_t dst_port;
			int8_t  proto;
			int8_t  pad1;
			int16_t pad2;
		};
		struct {
			int64_t hi64;
			int64_t lo64;
		};
	};
} ipv4_tuple5_t;

/**
 * Forwarding data base entry
 */
typedef struct fwd_db_entry_s {
	struct fwd_db_entry_s *next;          /**< Next entry on list */
	char                    oif[OIF_LEN]; /**< Output interface name */
	int			oif_id;	      /**< Output interface idx */
	odph_ethaddr_t		src_mac;      /**< Output source MAC */
	odph_ethaddr_t		dst_mac;      /**< Output destination MAC */
	ip_addr_range_t		subnet;       /**< Subnet for this router */
} fwd_db_entry_t;

/**
 * Forwarding data base
 */
typedef struct fwd_db_s {
	uint32_t          index;          /**< Next available entry */
	fwd_db_entry_t   *list;           /**< List of active routes */
	fwd_db_entry_t    array[MAX_DB];  /**< Entry storage */
} fwd_db_t;

/** Global pointer to fwd db */
extern fwd_db_t *fwd_db;

/**
 * Initialize FWD DB
 */
void init_fwd_db(void);

/**
 * Initialize forward lookup cache based on hash
 */
void init_fwd_hash_cache(void);

/**
 * Create a forwarding database entry
 *
 * String is of the format "SubNet,Intf,NextHopMAC"
 *
 * @param input  Pointer to string describing route
 * @param oif  Pointer to out interface name, as a return value
 * @param dst_mac  Pointer to dest mac for output packet, as a return value
 *
 * @return 0 if successful else -1
 */
int create_fwd_db_entry(char *input, char **oif, uint8_t **dst_mac);

/**
 * Scan FWD DB entries and resolve output queue and source MAC address
 *
 * @param intf   Interface name string
 * @param portid Output queue for packet transmit
 * @param mac    MAC address of this interface
 */
void resolve_fwd_db(char *intf, int portid, uint8_t *mac);

/**
 * Display one forwarding database entry
 *
 * @param entry  Pointer to entry to display
 */
void dump_fwd_db_entry(fwd_db_entry_t *entry);

/**
 * Display the forwarding database
 */
void dump_fwd_db(void);

/**
 * Find a matching forwarding database entry
 *
 * @param key  ipv4 tuple
 *
 * @return pointer to forwarding DB entry else NULL
 */
fwd_db_entry_t *find_fwd_db_entry(ipv4_tuple5_t *key);

#ifdef __cplusplus
}
#endif

#endif
