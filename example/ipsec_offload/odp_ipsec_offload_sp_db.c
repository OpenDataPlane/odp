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

#include <odp_ipsec_offload_sp_db.h>

/** Global pointer to sp db */
sp_db_t *sp_db;

void init_sp_db(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("shm_sp_db",
			      sizeof(sp_db_t),
			      ODP_CACHE_LINE_SIZE,
			      0);

	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Error: shared mem reserve failed.\n");

	sp_db = odp_shm_addr(shm);

	if (sp_db == NULL)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	memset(sp_db, 0, sizeof(*sp_db));
}

int create_sp_db_entry(char *input, int entries)
{
	int pos = 0, count = 0;
	char *local;
	char *str;
	char *save;
	char *token;
	sp_db_entry_t *entry = &sp_db->array[sp_db->index];

	/* Verify we have a good entry */
	if (MAX_DB <= sp_db->index)
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
					  &entry->src_subnet.addr,
					  &entry->src_subnet.mask);
			break;
		case 1:
			parse_ipv4_string(token,
					  &entry->dst_subnet.addr,
					  &entry->dst_subnet.mask);
			break;
		case 2:
			if (0 == strcmp(token, "in"))
				entry->input = TRUE;
			else
				entry->input = FALSE;
			break;
		case 3:
			if (0 == strcmp(token, "esp")) {
				entry->esp = TRUE;
			} else if (0 == strcmp(token, "ah")) {
				entry->ah = TRUE;
			} else if (0 == strcmp(token, "both")) {
				entry->esp = TRUE;
				entry->ah = TRUE;
			}
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
	if (4 != pos) {
		printf("ERROR: \"%s\" contains %d tokens, expected 4\n",
		       input,
		       pos);
		free(local);
		return -1;
	}

	/* Add route to the list */
	sp_db->index++;
	entry->next = sp_db->list;
	sp_db->list = entry;
	count++;
	while (count < entries) {
		sp_db_entry_t *new_entry = &sp_db->array[sp_db->index];

		/* Verify we have a good entry */
		if (MAX_DB <= sp_db->index)
			return -1;

		new_entry->src_subnet.addr = entry->src_subnet.addr + count;
		new_entry->src_subnet.mask = entry->src_subnet.mask;
		new_entry->dst_subnet.addr = entry->dst_subnet.addr + count;
		new_entry->dst_subnet.mask = entry->dst_subnet.mask;
		new_entry->input = entry->input;
		new_entry->esp = entry->esp;
		new_entry->ah = entry->ah;
		/* Add route to the list */
		sp_db->index++;
		new_entry->next = sp_db->list;
		sp_db->list = new_entry;
		count++;
	}

	free(local);
	return 0;
}

void dump_sp_db_entry(sp_db_entry_t *entry)
{
	char src_subnet_str[MAX_STRING];
	char dst_subnet_str[MAX_STRING];

	printf(" %s %s %s %s:%s\n",
	       ipv4_subnet_str(src_subnet_str, &entry->src_subnet),
	       ipv4_subnet_str(dst_subnet_str, &entry->dst_subnet),
	       entry->input ? "in" : "out",
	       entry->esp ? "esp" : "none",
	       entry->ah ? "ah" : "none");
}

void dump_sp_db(void)
{
	sp_db_entry_t *entry;

	printf("\n"
	       "Security policy table\n"
	       "---------------------\n");

	for (entry = sp_db->list; NULL != entry; entry = entry->next)
		dump_sp_db_entry(entry);
}
