/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <odp_l3fwd_db.h>

/** Jenkins hash support.
  *
  * Copyright (C) 2006 Bob Jenkins (bob_jenkins@burtleburtle.net)
  *
  * http://burtleburtle.net/bob/hash/
  *
  * These are the credits from Bob's sources:
  *
  * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
  *
  * These are functions for producing 32-bit hashes for hash table lookup.
  * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
  * are externally useful functions.  Routines to test the hash are included
  * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
  * the public domain.  It has no warranty.
  *
  * $FreeBSD$
  */
#define JHASH_GOLDEN_RATIO	0x9e3779b9
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))
#define FWD_BJ3_MIX(a, b, c) \
{ \
	a -= c; a ^= rot(c, 4); c += b; \
	b -= a; b ^= rot(a, 6); a += c; \
	c -= b; c ^= rot(b, 8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b, 4); b += a; \
}

/**
 * Compute hash value from a flow
 */
static inline
uint64_t l3fwd_calc_hash(ipv4_tuple5_t *key)
{
	uint64_t l4_ports = 0;
	uint32_t dst_ip, src_ip;

	src_ip = key->src_ip;
	dst_ip = key->dst_ip + JHASH_GOLDEN_RATIO;
	FWD_BJ3_MIX(src_ip, dst_ip, l4_ports);

	return l4_ports;
}

/**
 * Parse text string representing an IPv4 address or subnet
 *
 * String is of the format "XXX.XXX.XXX.XXX(/W)" where
 * "XXX" is decimal value and "/W" is optional subnet length
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr       Pointer to return IPv4 address, host endianness
 * @param depth      Pointer to subnet bit width
 * @return 0 if successful else -1
 */
static inline
int parse_ipv4_string(char *ipaddress, uint32_t *addr, uint32_t *depth)
{
	int b[4];
	int qualifier = 32;
	int converted;
	uint32_t addr_le;

	if (strchr(ipaddress, '/')) {
		converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
				   &b[3], &b[2], &b[1], &b[0],
				   &qualifier);
		if (5 != converted)
			return -1;
	} else {
		converted = sscanf(ipaddress, "%d.%d.%d.%d",
				   &b[3], &b[2], &b[1], &b[0]);
		if (4 != converted)
			return -1;
	}

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;
	if (!qualifier || (qualifier > 32))
		return -1;

	addr_le = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	*addr = odp_le_to_cpu_32(addr_le);
	*depth = qualifier;

	return 0;
}

/**
 * Generate text string representing IPv4 range/subnet, output
 * in "XXX.XXX.XXX.XXX/W" format
 *
 * @param b     Pointer to buffer to store string
 * @param range Pointer to IPv4 address range
 *
 * @return Pointer to supplied buffer
 */
static inline
char *ipv4_subnet_str(char *b, ip_addr_range_t *range)
{
	sprintf(b, "%d.%d.%d.%d/%d",
		0xFF & ((range->addr) >> 24),
		0xFF & ((range->addr) >> 16),
		0xFF & ((range->addr) >>  8),
		0xFF & ((range->addr) >>  0),
		range->depth);
	return b;
}

/**
 * Generate text string representing MAC address
 *
 * @param b     Pointer to buffer to store string
 * @param mac   Pointer to MAC address
 *
 * @return Pointer to supplied buffer
 */
static inline
char *mac_addr_str(char *b, odph_ethaddr_t *mac)
{
	uint8_t *byte;

	byte = mac->addr;
	sprintf(b, "%02X:%02X:%02X:%02X:%02X:%02X",
		byte[0], byte[1], byte[2], byte[3], byte[4], byte[5]);
	return b;
}

/**
 * Flow cache table entry
 */
typedef struct flow_entry_s {
	ipv4_tuple5_t key;		/**< match key */
	struct flow_entry_s *next;	/**< next entry in the bucket */
	fwd_db_entry_t *fwd_entry;	/**< entry info in db */
} flow_entry_t;

/**
 * Flow cache table bucket
 */
typedef struct flow_bucket_s {
	odp_rwlock_t	lock;	/**< Bucket lock*/
	flow_entry_t	*next;	/**< First flow entry in bucket*/
} flow_bucket_t;

/**
 * Flow hash table, fast lookup cache
 */
typedef struct flow_table_s {
	odp_rwlock_t flow_lock;	/**< flow table lock*/
	flow_entry_t *flows;	/**< flow store */
	flow_bucket_t *bucket;	/**< bucket store */
	uint32_t bkt_cnt;
	uint32_t flow_cnt;
	uint32_t next_flow;	/**< next available flow in the store */
} flow_table_t;

static flow_table_t fwd_lookup_cache;

static void create_fwd_hash_cache(void)
{
	odp_shm_t		hash_shm;
	flow_bucket_t		*bucket = NULL;
	flow_entry_t		*flows;
	uint32_t		bucket_count, flow_count, size;
	uint32_t		i;

	flow_count = FWD_MAX_FLOW_COUNT;
	bucket_count = flow_count / FWD_DEF_BUCKET_ENTRIES;

	/*Reserve memory for Routing hash table*/
	size = sizeof(flow_bucket_t) * bucket_count +
		sizeof(flow_entry_t) * flow_count;
	hash_shm = odp_shm_reserve("flow_table", size, ODP_CACHE_LINE_SIZE, 0);
	if (hash_shm != ODP_SHM_INVALID)
		bucket = odp_shm_addr(hash_shm);

	if (!bucket) {
		/* Try the second time with small request */
		flow_count /= 4;
		bucket_count = flow_count / FWD_DEF_BUCKET_ENTRIES;
		size = sizeof(flow_bucket_t) * bucket_count +
			sizeof(flow_entry_t) * flow_count;
		hash_shm = odp_shm_reserve("flow_table", size,
					   ODP_CACHE_LINE_SIZE, 0);
		if (hash_shm == ODP_SHM_INVALID) {
			ODPH_ERR("Error: shared mem reserve failed.\n");
			exit(EXIT_FAILURE);
		}

		bucket = odp_shm_addr(hash_shm);
		if (!bucket) {
			ODPH_ERR("Error: shared mem alloc failed.\n");
			exit(-1);
		}
	}

	size = sizeof(flow_bucket_t) * bucket_count;
	flows = (flow_entry_t *)(void *)((char *)bucket + size);

	fwd_lookup_cache.bucket = bucket;
	fwd_lookup_cache.bkt_cnt = bucket_count;
	fwd_lookup_cache.flows = flows;
	fwd_lookup_cache.flow_cnt = flow_count;

	/*Initialize bucket locks*/
	for (i = 0; i < bucket_count; i++) {
		bucket = &fwd_lookup_cache.bucket[i];
		odp_rwlock_init(&bucket->lock);
		bucket->next = NULL;
	}

	memset(flows, 0, sizeof(flow_entry_t) * flow_count);
	odp_rwlock_init(&fwd_lookup_cache.flow_lock);
	fwd_lookup_cache.next_flow = 0;
}

static inline flow_entry_t *get_new_flow(void)
{
	uint32_t next;
	flow_entry_t *flow = NULL;

	odp_rwlock_write_lock(&fwd_lookup_cache.flow_lock);
	next = fwd_lookup_cache.next_flow;
	if (next < fwd_lookup_cache.flow_cnt) {
		flow = &fwd_lookup_cache.flows[next];
		fwd_lookup_cache.next_flow++;
	}
	odp_rwlock_write_unlock(&fwd_lookup_cache.flow_lock);

	return flow;
}

static inline
int match_key_flow(ipv4_tuple5_t *key, flow_entry_t *flow)
{
	if (key->hi64 == flow->key.hi64 && key->lo64 == flow->key.lo64)
		return 1;

	return 0;
}

static inline
flow_entry_t *lookup_fwd_cache(ipv4_tuple5_t *key, flow_bucket_t *bucket)
{
	flow_entry_t *rst;

	odp_rwlock_read_lock(&bucket->lock);
	for (rst = bucket->next; rst != NULL; rst = rst->next) {
		if (match_key_flow(key, rst))
			break;
	}
	odp_rwlock_read_unlock(&bucket->lock);

	return rst;
}

static inline
flow_entry_t *insert_fwd_cache(ipv4_tuple5_t *key,
			       flow_bucket_t *bucket,
			       fwd_db_entry_t *entry)
{
	flow_entry_t *flow;

	if (!entry)
		return NULL;

	flow = get_new_flow();
	if (!flow)
		return NULL;

	flow->key = *key;
	flow->fwd_entry = entry;

	odp_rwlock_write_lock(&bucket->lock);
	if (bucket->next)
		flow->next = bucket->next;
	bucket->next = flow;
	odp_rwlock_write_unlock(&bucket->lock);

	return flow;
}

void init_fwd_hash_cache(void)
{
	fwd_db_entry_t *entry;
	flow_entry_t *flow;
	flow_bucket_t *bucket;
	uint64_t hash;
	uint32_t i, nb_hosts;
	ipv4_tuple5_t key;

	create_fwd_hash_cache();

	/**
	 * warm up the lookup cache with possible hosts.
	 * with millions flows, save significant time during runtime.
	 */
	memset(&key, 0, sizeof(key));
	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		nb_hosts = 1 << (32 - entry->subnet.depth);
		for (i = 0; i < nb_hosts; i++) {
			key.dst_ip = entry->subnet.addr + i;
			hash = l3fwd_calc_hash(&key);
			hash &= fwd_lookup_cache.bkt_cnt - 1;
			bucket = &fwd_lookup_cache.bucket[hash];
			flow = lookup_fwd_cache(&key, bucket);
			if (flow)
				return;

			flow = insert_fwd_cache(&key, bucket, entry);
			if (!flow)
				goto out;
		}
	}
out:
	return;
}

/** Global pointer to fwd db */
fwd_db_t *fwd_db;

void init_fwd_db(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("shm_fwd_db",
			      sizeof(fwd_db_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	fwd_db = odp_shm_addr(shm);

	if (fwd_db == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(fwd_db, 0, sizeof(*fwd_db));
}

int create_fwd_db_entry(char *input, char **oif, uint8_t **dst_mac)
{
	int pos = 0;
	char *local;
	char *str;
	char *save;
	char *token;
	fwd_db_entry_t *entry = &fwd_db->array[fwd_db->index];

	*oif = NULL;
	*dst_mac = NULL;

	/* Verify we haven't run out of space */
	if (MAX_DB <= fwd_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (NULL == local)
		return -1;
	strcpy(local, input);

	/* Setup for using "strtok_r" to search input string */
	str = local;
	save = NULL;

	/* Parse tokens separated by ',' */
	while (NULL != (token = strtok_r(str, ",", &save))) {
		str = NULL;  /* reset str for subsequent strtok_r calls */

		/* Parse token based on its position */
		switch (pos) {
		case 0:
			parse_ipv4_string(token,
					  &entry->subnet.addr,
					  &entry->subnet.depth);
			break;
		case 1:
			strncpy(entry->oif, token, OIF_LEN - 1);
			entry->oif[OIF_LEN - 1] = 0;
			*oif = entry->oif;
			break;
		case 2:
			if (odph_eth_addr_parse(&entry->dst_mac, token) < 0) {
				free(local);
				return -1;
			}
			*dst_mac = entry->dst_mac.addr;
			break;

		default:
			printf("ERROR: extra token \"%s\" at position %d\n",
			       token, pos);
			break;
		}

		/* Advance to next position */
		pos++;
	}

	/* Add route to the list */
	fwd_db->index++;
	entry->next = fwd_db->list;
	fwd_db->list = entry;

	free(local);
	return 0;
}

void resolve_fwd_db(char *intf, int portid, uint8_t *mac)
{
	fwd_db_entry_t *entry;

	/* Walk the list and attempt to set output and MAC */
	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if (strcmp(intf, entry->oif))
			continue;

		entry->oif_id = portid;
		memcpy(entry->src_mac.addr, mac, ODPH_ETHADDR_LEN);
	}
}

void dump_fwd_db_entry(fwd_db_entry_t *entry)
{
	char subnet_str[MAX_STRING];
	char mac_str[MAX_STRING];

	mac_addr_str(mac_str, &entry->dst_mac);
	printf("%-32s%-32s%-16s\n",
	       ipv4_subnet_str(subnet_str, &entry->subnet),
	       entry->oif, mac_str);
}

void dump_fwd_db(void)
{
	fwd_db_entry_t *entry;

	printf("Routing table\n"
	       "-----------------\n"
	       "%-32s%-32s%-16s\n",
	       "subnet", "next_hop", "dest_mac");

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		dump_fwd_db_entry(entry);

	printf("\n");
}

fwd_db_entry_t *find_fwd_db_entry(ipv4_tuple5_t *key)
{
	fwd_db_entry_t *entry;
	flow_entry_t *flow;
	flow_bucket_t *bucket;
	uint64_t hash;
	ipv4_tuple5_t newkey;

	newkey.hi64 = 0;
	newkey.lo64 = 0;
	newkey.dst_ip = key->dst_ip;
	key = &newkey;

	/* first find in cache */
	hash = l3fwd_calc_hash(key);
	hash &= fwd_lookup_cache.bkt_cnt - 1;
	bucket = &fwd_lookup_cache.bucket[hash];
	flow = lookup_fwd_cache(key, bucket);
	if (flow)
		return flow->fwd_entry;

	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		uint32_t mask;

		mask = ((1u << entry->subnet.depth) - 1) <<
			(32 - entry->subnet.depth);

		if (entry->subnet.addr == (key->dst_ip & mask))
			break;
	}

	insert_fwd_cache(key, bucket, entry);

	return entry;
}
