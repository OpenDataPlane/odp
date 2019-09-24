/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

static void print_prefix_info(
		const char *msg, uint32_t ip, uint8_t cidr)
{
	int i = 0;
	uint8_t *ptr = (uint8_t *)(&ip);

	printf("%s IP prefix: ", msg);
	for (i = 3; i >= 0; i--) {
		if (i != 3)
			printf(".");
		printf("%d", ptr[i]);
	}
	printf("/%d\n", cidr);
}

/*
 * Basic sequence of operations for a single key:
 *	- put short prefix
 *	- put long prefix
 *	- get (hit long prefix)
 *	- remove long prefix
 *	- get (hit short prefix)
 */
static int test_ip_lookup_table(void)
{
	odph_iplookup_prefix_t prefix1, prefix2;
	odph_table_t table;
	int ret;
	uint64_t value1 = 1, value2 = 2, result = 0;
	uint32_t lkp_ip = 0;

	table = odph_iplookup_table_create(
			"prefix_test", 0, 0, sizeof(uint32_t));
	if (table == NULL) {
		printf("IP prefix lookup table creation failed\n");
		return -1;
	}

	ret = odph_ipv4_addr_parse(&prefix1.ip, "192.168.0.0");
	if (ret < 0) {
		printf("Failed to get IP addr from str\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}
	prefix1.cidr = 11;

	ret = odph_ipv4_addr_parse(&prefix2.ip, "192.168.0.0");
	if (ret < 0) {
		printf("Failed to get IP addr from str\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}
	prefix2.cidr = 24;

	ret = odph_ipv4_addr_parse(&lkp_ip, "192.168.0.1");
	if (ret < 0) {
		printf("Failed to get IP addr from str\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	/* test with standard put/get/remove functions */
	ret = odph_iplookup_table_put_value(table, &prefix1, &value1);
	print_prefix_info("Add", prefix1.ip, prefix1.cidr);
	if (ret < 0) {
		printf("Failed to add ip prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	ret = odph_iplookup_table_get_value(table, &lkp_ip, &result, 0);
	print_prefix_info("Lkp", lkp_ip, 32);
	if (ret < 0 || result != 1) {
		printf("Failed to find longest prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	/* add a longer prefix */
	ret = odph_iplookup_table_put_value(table, &prefix2, &value2);
	print_prefix_info("Add", prefix2.ip, prefix2.cidr);
	if (ret < 0) {
		printf("Failed to add ip prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	ret = odph_iplookup_table_get_value(table, &lkp_ip, &result, 0);
	print_prefix_info("Lkp", lkp_ip, 32);
	if (ret < 0 || result != 2) {
		printf("Failed to find longest prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	ret = odph_iplookup_table_remove_value(table, &prefix2);
	print_prefix_info("Del", prefix2.ip, prefix2.cidr);
	if (ret < 0) {
		printf("Failed to delete ip prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	ret = odph_iplookup_table_get_value(table, &lkp_ip, &result, 0);
	print_prefix_info("Lkp", lkp_ip, 32);
	if (ret < 0 || result != 1) {
		printf("Error: found result ater deleting\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	ret = odph_iplookup_table_remove_value(table, &prefix1);
	print_prefix_info("Del", prefix1.ip, prefix1.cidr);
	if (ret < 0) {
		printf("Failed to delete prefix\n");
		odph_iplookup_table_destroy(table);
		return -1;
	}

	odph_iplookup_table_destroy(table);
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

	if (test_ip_lookup_table() < 0)
		printf("Test failed\n");
	else
		printf("All tests passed\n");

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
