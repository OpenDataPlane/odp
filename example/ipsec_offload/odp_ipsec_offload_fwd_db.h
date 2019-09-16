/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_IPSEC_FWD_DB_H_
#define ODP_IPSEC_FWD_DB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp.h>
#include <odp/helper/odph_api.h>

#include <odp_ipsec_offload_misc.h>

#define OIF_LEN 32

/**
 * Forwarding data base entry
 */

typedef struct fwd_db_entry_s {
	struct fwd_db_entry_s *next;          /**< Next entry on list */
	char                   oif[OIF_LEN];  /**< Output interface name */
	odp_pktout_queue_t	pktout;         /**< Output transmit queue */
	uint8_t   src_mac[ODPH_ETHADDR_LEN];  /**< Output source MAC */
	uint8_t   dst_mac[ODPH_ETHADDR_LEN];  /**< Output destination MAC */
	ip_addr_range_t        subnet;        /**< Subnet for this router */
} fwd_db_entry_t;

/**
 * Forwarding data base global structure
 */
typedef struct fwd_db_s {
	uint32_t          index;          /**< Next available entry */
	fwd_db_entry_t   *list;           /**< List of active routes */
	fwd_db_entry_t    array[MAX_DB];  /**< Entry storage */
} fwd_db_t;

/** Global pointer to fwd db */
extern fwd_db_t *fwd_db;

/**
 * Flow cache table entry
 */
typedef struct {
	void			*next;	/**< Pointer to next flow in list*/
	uint32_t		l3_src;	/**< Source IP Address*/
	uint32_t		l3_dst;	/**< Destination IP Address*/
	ipsec_out_entry_t	out_port; /**< Out interface of matching flow*/
} flow_entry_t;

/**
 * Flow cache table bucket
 */
typedef struct {
	odp_spinlock_t		lock;	/**< Bucket lock*/
	flow_entry_t		*next;	/**< Pointer to first flow entry in bucket*/
} flow_bucket_t;

/**
* Pointers to Flow cache tables
*/
extern flow_bucket_t *flow_table;

extern flow_bucket_t *ipsec_out_flow_table;

extern flow_bucket_t *ipsec_in_flow_table;

/**
 * Number of buckets in hash table
 */
extern uint32_t bucket_count;

/*
 * Allocate and Initialize routing table with default Route entries.
 *
 */
void init_routing_table(void);

/*
 * Searches flow entry in given hash bucket according to given 5-tuple
 * information
 *
 * @param sip           Source IP Address
 * @param dip           Destination IP Address
 * @param sport         Source Port Number
 * @param dport         Destination Port Number
 * @param proto         IP protocol
 * @param bucket        Hash Bucket
 *
 * @return Matching flow entry
 */
static inline flow_entry_t *route_flow_lookup_in_bucket(uint32_t sip,
							uint32_t dip,
							void *bucket)
{
	flow_entry_t      *flow, *head;

	head = ((flow_bucket_t *)bucket)->next;
	for (flow = head; flow != NULL; flow = flow->next) {
		if ((flow->l3_src == sip) && (flow->l3_dst == dip))
			return flow;
	}
	return NULL;
}

/**
 * Insert the flow into given hash bucket
 *
 * @param flow		Which is to be inserted
 * @param bucket	Target Hash Bucket
 */
static inline void route_flow_insert_in_bucket(flow_entry_t *flow,
					       void *bucket)
{
	flow_entry_t *temp;
	flow_bucket_t *bkt = (flow_bucket_t *)bucket;

	if (!flow) {
		ODPH_ERR("Invalid flow entry passed\n");
		return;
	}

	LOCK(&bkt->lock);
	/*Check that entry already exist or not*/
	temp = route_flow_lookup_in_bucket(flow->l3_src, flow->l3_dst, bkt);
	if (temp) {
		UNLOCK(&bkt->lock);
		return;
	}

	if (!bkt->next) {
		bkt->next = flow;
	} else {
		temp = bkt->next;
		flow->next = temp;
		bkt->next = flow;
	}
	UNLOCK(&bkt->lock);
}

/** Initialize FWD DB */
void init_fwd_db(void);

/**
 * Create a forwarding database entry
 *
 * String is of the format "SubNet:Intf:NextHopMAC"
 *
 * @param input  Pointer to string describing route
 * @param if_names  Array of Name of the interfaces available
 * @param if_count  number of interfaces in if_names array
 * @param entries number of entries
 *
 * @return 0 if successful else -1
 */
int create_fwd_db_entry(char *input, char **if_names, int if_count,
			int entries);

/**
 * Scan FWD DB entries and resolve output queue and source MAC address
 *
 * @param intf   Interface name string
 * @param outq   Output queue for packet transmit
 * @param mac    MAC address of this interface
 */
void resolve_fwd_db(char *intf, odp_pktout_queue_t pktout, uint8_t *mac);

/**
 * Display one fowarding database entry
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
 * @param dst_ip  Destination IPv4 address
 *
 * @return pointer to forwarding DB entry else NULL
 */
fwd_db_entry_t *find_fwd_db_entry(uint32_t dst_ip);

#ifdef __cplusplus
}
#endif

#endif
