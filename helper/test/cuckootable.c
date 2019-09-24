/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <time.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/*******************************************************************************
 * Hash function performance test configuration section.
 *
 * The five arrays below control what tests are performed. Every combination
 * from the array entries is tested.
 */
/******************************************************************************/

/* 5-tuple key type */
struct flow_key {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t proto;
} __packed;

/*
 * Print out result of unit test hash operation.
 */
static void print_key_info(
		const char *msg, const struct flow_key *key)
{
	const uint8_t *p = (const uint8_t *)key;
	unsigned i;

	printf("%s key:0x", msg);
	for (i = 0; i < sizeof(struct flow_key); i++)
		printf("%02X", p[i]);
	printf("\n");
}

static double get_time_diff(struct timeval *start, struct timeval *end)
{
	int sec = end->tv_sec - start->tv_sec;
	int usec = end->tv_usec - start->tv_usec;

	if (usec < 0) {
		sec--;
		usec += 1000000;
	}
	double diff = sec + (double)usec / 1000000;

	return diff;
}

/** Create IPv4 address */
#define IPv4(a, b, c, d) ((uint32_t)(((a) & 0xff) << 24) | \
	(((b) & 0xff) << 16) | \
	(((c) & 0xff) << 8)  | \
	((d) & 0xff))

/* Keys used by unit test functions */
static struct flow_key keys[5] = { {
	.ip_src = IPv4(0x03, 0x02, 0x01, 0x00),
	.ip_dst = IPv4(0x07, 0x06, 0x05, 0x04),
	.port_src = 0x0908,
	.port_dst = 0x0b0a,
	.proto = 0x0c,
}, {
	.ip_src = IPv4(0x13, 0x12, 0x11, 0x10),
	.ip_dst = IPv4(0x17, 0x16, 0x15, 0x14),
	.port_src = 0x1918,
	.port_dst = 0x1b1a,
	.proto = 0x1c,
}, {
	.ip_src = IPv4(0x23, 0x22, 0x21, 0x20),
	.ip_dst = IPv4(0x27, 0x26, 0x25, 0x24),
	.port_src = 0x2928,
	.port_dst = 0x2b2a,
	.proto = 0x2c,
}, {
	.ip_src = IPv4(0x33, 0x32, 0x31, 0x30),
	.ip_dst = IPv4(0x37, 0x36, 0x35, 0x34),
	.port_src = 0x3938,
	.port_dst = 0x3b3a,
	.proto = 0x3c,
}, {
	.ip_src = IPv4(0x43, 0x42, 0x41, 0x40),
	.ip_dst = IPv4(0x47, 0x46, 0x45, 0x44),
	.port_src = 0x4948,
	.port_dst = 0x4b4a,
	.proto = 0x4c,
} };

/*
 * Basic sequence of operations for a single key:
 *	- put
 *	- get (hit)
 *	- remove
 *	- get (miss)
 */
static int test_put_remove(void)
{
	odph_table_t table;
	odph_table_ops_t *ops;

	ops = &odph_cuckoo_table_ops;

	/* test with standard put/get/remove functions */
	int ret;

	table = ops->f_create("put_remove", 10, sizeof(struct flow_key), 0);
	if (table == NULL) {
		printf("cuckoo hash table creation failed\n");
		return -1;
	}

	ret = odph_cuckoo_table_put_value(table, &keys[0], NULL);
	print_key_info("Add", &keys[0]);
	if (ret < 0) {
		printf("failed to add key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_get_value(table, &keys[0], NULL, 0);
	print_key_info("Lkp", &keys[0]);
	if (ret < 0) {
		printf("failed to find key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_remove_value(table, &keys[0]);
	print_key_info("Del", &keys[0]);
	if (ret < 0) {
		printf("failed to delete key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_get_value(table, &keys[0], NULL, 0);
	print_key_info("Lkp", &keys[0]);
	if (ret >= 0) {
		printf("error: found key after deleting!\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	odph_cuckoo_table_destroy(table);
	return 0;
}

/*
 * Sequence of operations for a single key:
 * key type : struct flow_key
 * value type: uint8_t
 *	- remove: miss
 *	- put
 *	- get: hit
 *	- put: update
 *	- get: hit (updated data)
 *	- remove: hit
 *	- remove: miss
 */
static int test_put_update_remove(void)
{
	odph_table_t table;
	int ret;
	uint8_t val1 = 1, val2 = 2, val = 0;

	table = odph_cuckoo_table_create(
			"put_update_remove",
			10, sizeof(struct flow_key), sizeof(uint8_t));
	if (table == NULL) {
		printf("failed to create table\n");
		return -1;
	}

	ret = odph_cuckoo_table_remove_value(table, &keys[0]);
	print_key_info("Del", &keys[0]);
	if (ret >= 0) {
		printf("error: found non-existent key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_put_value(table, &keys[0], &val1);
	print_key_info("Add", &keys[0]);
	if (ret < 0) {
		printf("failed to add key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_get_value(
			table, &keys[0], &val, sizeof(uint8_t));
	print_key_info("Lkp", &keys[0]);
	if (ret < 0) {
		printf("failed to find key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_put_value(table, &keys[0], &val2);
	if (ret < 0) {
		printf("failed to re-add key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_get_value(
			table, &keys[0], &val, sizeof(uint8_t));
	print_key_info("Lkp", &keys[0]);
	if (ret < 0) {
		printf("failed to find key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_remove_value(table, &keys[0]);
	print_key_info("Del", &keys[0]);
	if (ret < 0) {
		printf("failed to delete key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	ret = odph_cuckoo_table_remove_value(table, &keys[0]);
	print_key_info("Del", &keys[0]);
	if (ret >= 0) {
		printf("error: deleted already deleted key\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	odph_cuckoo_table_destroy(table);
	return 0;
}

/*
 * Sequence of operations for find existing hash table
 *
 *  - create table
 *  - find existing table: hit
 *  - find non-existing table: miss
 *
 */
static int test_table_lookup(void)
{
	odph_table_t table, result;

	/* Create cuckoo hash table. */
	table = odph_cuckoo_table_create("table_lookup", 10, 4, 0);
	if (table == NULL) {
		printf("failed to create table\n");
		return -1;
	}

	/* Try to find existing hash table */
	result = odph_cuckoo_table_lookup("table_lookup");
	if (result != table) {
		printf("error: could not find existing table\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	/* Try to find non-existing hash table */
	result = odph_cuckoo_table_lookup("non_existing");
	if (result != NULL) {
		printf("error: found table that shouldn't exist.\n");
		odph_cuckoo_table_destroy(table);
		return -1;
	}

	/* Cleanup. */
	odph_cuckoo_table_destroy(table);
	return 0;
}

/*
 * Sequence of operations for 5 keys
 *	- put keys
 *	- get keys: hit
 *	- remove keys : hit
 *	- get keys: miss
 */
static int test_five_keys(void)
{
	odph_table_t table;
	unsigned i;
	int ret;

	table = odph_cuckoo_table_create(
			"five_keys", 10, sizeof(struct flow_key), 0);
	if (table == NULL) {
		printf("failed to create table\n");
		return -1;
	}

	/* put */
	for (i = 0; i < 5; i++) {
		ret = odph_cuckoo_table_put_value(table, &keys[i], NULL);
		print_key_info("Add", &keys[i]);
		if (ret < 0) {
			printf("failed to add key %d\n", i);
			odph_cuckoo_table_destroy(table);
			return -1;
		}
	}

	/* get */
	for (i = 0; i < 5; i++) {
		ret = odph_cuckoo_table_get_value(table, &keys[i], NULL, 0);
		print_key_info("Lkp", &keys[i]);
		if (ret < 0) {
			printf("failed to find key %d\n", i);
			odph_cuckoo_table_destroy(table);
			return -1;
		}
	}

	/* remove */
	for (i = 0; i < 5; i++) {
		ret = odph_cuckoo_table_remove_value(table, &keys[i]);
		print_key_info("Del", &keys[i]);
		if (ret < 0) {
			printf("failed to delete key %d\n", i);
			odph_cuckoo_table_destroy(table);
			return -1;
		}
	}

	/* get */
	for (i = 0; i < 5; i++) {
		ret = odph_cuckoo_table_get_value(table, &keys[i], NULL, 0);
		print_key_info("Lkp", &keys[i]);
		if (ret >= 0) {
			printf("found non-existing key %d\n", i);
			odph_cuckoo_table_destroy(table);
			return -1;
		}
	}

	odph_cuckoo_table_destroy(table);
	return 0;
}

#define BUCKET_ENTRIES 4
#define HASH_ENTRIES_MAX 1048576
/*
 * Do tests for cuchoo tabke creation with bad parameters.
 */
static int test_creation_with_bad_parameters(void)
{
	odph_table_t table;

	table = odph_cuckoo_table_create(
			"bad_param_0", HASH_ENTRIES_MAX + 1, 4, 0);
	if (table != NULL) {
		odph_cuckoo_table_destroy(table);
		printf("Impossible creating table successfully with entries in parameter exceeded\n");
		return -1;
	}

	table = odph_cuckoo_table_create(
			"bad_param_1", BUCKET_ENTRIES - 1, 4, 0);
	if (table != NULL) {
		odph_cuckoo_table_destroy(table);
		printf("Impossible creating hash successfully if entries less than bucket_entries in parameter\n");
		return -1;
	}

	table = odph_cuckoo_table_create("bad_param_2", 10, 0, 0);
	if (table != NULL) {
		odph_cuckoo_table_destroy(table);
		printf("Impossible creating hash successfully if key_len in parameter is zero\n");
		return -1;
	}

	printf("# Test successful. No more errors expected\n");

	return 0;
}

#define PERFORMANCE_CAPACITY 4000

/*
 * Test the performance of cuckoo hash table.
 *   table capacity : 1,000,000
 *   key size : 4 bytes
 *   value size : 0
 * Insert at most number random keys into the table. If one
 * insertion is failed, the rest insertions will be cancelled.
 * The table utilization of the report will show actual number
 * of items inserted.
 * Then search all inserted items.
 */
static int test_performance(int number)
{
	odph_table_t table;

	/* generate random keys */
	uint8_t *key_space = NULL;
	const void **key_ptr = NULL;
	unsigned key_len = 4, j;
	unsigned elem_num = (number > PERFORMANCE_CAPACITY) ?
						PERFORMANCE_CAPACITY : number;
	unsigned key_num = key_len * elem_num;

	key_space = (uint8_t *)malloc(key_num);
	if (key_space == NULL)
		return -ENOENT;

	key_ptr = (const void **)malloc(sizeof(void *) * elem_num);
	if (key_ptr == NULL) {
		free(key_space);
		return -ENOENT;
	}

	for (j = 0; j < key_num; j++) {
		key_space[j] = rand() % 255;
		if (j % key_len == 0)
			key_ptr[j / key_len] = &key_space[j];
	}

	unsigned num;
	int ret = 0;
	struct timeval start, end;
	double add_time = 0;

	fflush(stdout);
	table = odph_cuckoo_table_create(
			"performance_test", PERFORMANCE_CAPACITY, key_len, 0);
	if (table == NULL) {
		printf("cuckoo table creation failed\n");
		free(key_ptr);
		free(key_space);
		return -ENOENT;
	}

	/* insert (put) */
	gettimeofday(&start, 0);
	for (j = 0; j < elem_num; j++) {
		ret = odph_cuckoo_table_put_value(
				table, &key_space[j * key_len], NULL);
		if (ret < 0)
			break;
	}
	gettimeofday(&end, 0);
	num = j;
	add_time = get_time_diff(&start, &end);
	printf(
		"add %u/%u (%.2f) items, time = %.9lfs\n",
		num, PERFORMANCE_CAPACITY,
		(double)num / PERFORMANCE_CAPACITY, add_time);

	/* search (get) */
	gettimeofday(&start, 0);
	for (j = 0; j < num; j++) {
		ret = odph_cuckoo_table_get_value(
				table, &key_space[j * key_len], NULL, 0);

		if (ret < 0)
			printf("lookup error\n");
	}
	gettimeofday(&end, 0);
	printf(
			"lookup %u items, time = %.9lfs\n",
			num, get_time_diff(&start, &end));

	odph_cuckoo_table_destroy(table);
	free(key_ptr);
	free(key_space);
	return ret;
}

/*
 * Do all unit and performance tests.
 */
static int
test_cuckoo_hash_table(void)
{
	if (test_put_remove() < 0)
		return -1;
	if (test_table_lookup() < 0)
		return -1;
	if (test_put_update_remove() < 0)
		return -1;
	if (test_five_keys() < 0)
		return -1;
	if (test_creation_with_bad_parameters() < 0)
		return -1;
	if (test_performance(950000) < 0)
		return -1;

	return 0;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_instance_t instance;
	int ret = 0;

	ret = odp_init_global(&instance, NULL, NULL);
	if (ret != 0) {
		fprintf(stderr, "Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	if (ret != 0) {
		fprintf(stderr, "Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	srand(time(0));
	ret = test_cuckoo_hash_table();

	if (ret < 0)
		printf("cuckoo hash table test fail!!\n");
	else
		printf("All Tests pass!!\n");

	if (odp_term_local()) {
		fprintf(stderr, "Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		fprintf(stderr, "Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}
