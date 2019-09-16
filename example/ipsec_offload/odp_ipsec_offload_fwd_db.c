/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* enable strtok */
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <string.h>

#include <odp.h>
#include <odp/helper/odph_api.h>

#include <odp_ipsec_offload_fwd_db.h>

/**
 * Pointer to Flow cache table
 */
flow_bucket_t *flow_table;

/**
 * bucket count. It will be updated with user argument if provided
 */
uint32_t bucket_count = DEFAULT_BUCKET_COUNT;

/** Global pointer to fwd db */
fwd_db_t *fwd_db;

void init_routing_table(void)
{
	odp_shm_t		hash_shm;
	uint32_t		i;
	flow_bucket_t		*bucket;

	/*Reserve memory for Routing hash table*/
	hash_shm = odp_shm_reserve("route_table",
				   sizeof(flow_bucket_t) * bucket_count,
				   ODP_CACHE_LINE_SIZE, 0);
	if (hash_shm == ODP_SHM_INVALID)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	flow_table = odp_shm_addr(hash_shm);
	if (!flow_table)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	/*Inialize Locks*/
	for (i = 0; i < bucket_count; i++) {
		bucket = &flow_table[i];
		LOCK_INIT(&bucket->lock);
	}

	memset(flow_table, 0, bucket_count * sizeof(flow_bucket_t));
}

void init_fwd_db(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("shm_fwd_db",
			      sizeof(fwd_db_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Error: shared mem reserve failed.\n");

	fwd_db = odp_shm_addr(shm);

	if (fwd_db == NULL)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	memset(fwd_db, 0, sizeof(*fwd_db));
}

int create_fwd_db_entry(char *input, char **if_names, int if_count, int entries)
{
	int pos = 0, i, match = 0, count = 0;
	char *local;
	char *str;
	char *save;
	char *token;
	fwd_db_entry_t *entry = &fwd_db->array[fwd_db->index];

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

	/* Parse tokens separated by ':' */
	while (NULL != (token = strtok_r(str, ":", &save))) {
		str = NULL;  /* reset str for subsequent strtok_r calls */

		/* Parse token based on its position */
		switch (pos) {
		case 0:
			parse_ipv4_string(token,
					  &entry->subnet.addr,
					  &entry->subnet.mask);
			break;
		case 1:
			strncpy(entry->oif, token, OIF_LEN - 1);
			entry->oif[OIF_LEN - 1] = 0;
			for (i = 0; i < if_count; i++) {
				if (!strcmp(if_names[i], entry->oif)) {
					match = 1;
					break;
				}
			}
			if (!match) {
				printf("ERROR: interface name not correct for route\n");
				free(local);
				return -1;
			}
			break;
		case 2:
			parse_mac_string(token, entry->dst_mac);
			break;
		default:
			printf("ERROR: extra token \"%s\" at position %d\n",
			       token, pos);
			break;
		}

		/* Advance to next position */
		pos++;
	}

	/* Verify we parsed exactly the number of tokens we expected */
	if (3 != pos) {
		printf("ERROR: \"%s\" contains %d tokens, expected 3\n",
		       input,
		       pos);
		free(local);
		return -1;
	}

	/* Add route to the list */
	fwd_db->index++;
	entry->next = fwd_db->list;
	fwd_db->list = entry;

	count++;

	while (count < entries) {
		fwd_db_entry_t *new_entry = &fwd_db->array[fwd_db->index];

		/* Verify we haven't run out of space */
		if (MAX_DB <= fwd_db->index)
			return -1;

		new_entry->subnet.addr = entry->subnet.addr + count;
		new_entry->subnet.mask = entry->subnet.mask;
		strncpy(new_entry->oif, entry->oif, OIF_LEN - 1);
		new_entry->oif[OIF_LEN - 1] = 0;
		new_entry->dst_mac[0] = entry->dst_mac[0];
		new_entry->dst_mac[1] = entry->dst_mac[1];
		new_entry->dst_mac[2] = entry->dst_mac[2];
		new_entry->dst_mac[3] = entry->dst_mac[3];
		new_entry->dst_mac[4] = entry->dst_mac[4];
		new_entry->dst_mac[5] = entry->dst_mac[5];

		/* Add route to the list */
		fwd_db->index++;
		new_entry->next = fwd_db->list;
		fwd_db->list = new_entry;
		count++;
	}

	free(local);
	return 0;
}

void resolve_fwd_db(char *intf, odp_pktout_queue_t pktout, uint8_t *mac)
{
	fwd_db_entry_t *entry;

	/* Walk the list and attempt to set output queue and MAC */
	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if (strcmp(intf, entry->oif))
			continue;

		entry->pktout = pktout;
		memcpy(entry->src_mac, mac, ODPH_ETHADDR_LEN);
	}
}

void dump_fwd_db_entry(fwd_db_entry_t *entry)
{
	char subnet_str[MAX_STRING];
	char mac_str[MAX_STRING];

	printf(" %s %s %s\n",
	       ipv4_subnet_str(subnet_str, &entry->subnet),
	       entry->oif,
	       mac_addr_str(mac_str, entry->dst_mac));
}

void dump_fwd_db(void)
{
	fwd_db_entry_t *entry;

	printf("\n"
	       "Routing table\n"
	       "-------------\n");

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		dump_fwd_db_entry(entry);
}

fwd_db_entry_t *find_fwd_db_entry(uint32_t dst_ip)
{
	fwd_db_entry_t *entry;

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		if (entry->subnet.addr == (dst_ip & entry->subnet.mask))
			break;
	return entry;
}
