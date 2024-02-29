/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/**
 * Address Resolution Protocol (ARP)
 * Description: Once a route has been identified for an IP packet (so the
 * output interface and the IP address of the next hop station are known),
 * the MAC address of the next hop station is needed in order to send this
 * packet onto the next leg of the journey towards its destination
 * (as identified by its destination IP address). The MAC address of the next
 * hop station becomes the destination MAC address of the outgoing
 * Ethernet frame.
 * Hash table name: ARP table
 * Number of keys: Thousands
 * Key format: The pair of (Output interface, Next Hop IP address),
 *        which is typically 5 bytes for IPv4 and 17 bytes for IPv6.
 * value (data): MAC address of the next hop station (6 bytes).
 */

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_instance_t instance;
	int ret = 0;
	odph_table_t table;
	odph_table_t tmp_tbl;
	odph_table_ops_t *test_ops;
	char tmp[32];
	char key1[] = { 0, 10, 11, 12, 13, };
	char key2[] = { 1, 14, 15, 16, 17, };
	char key3[] = { 2, 18, 19, 20, 21, };
	char mac_addr1[] = { 30, 31, 32, 33, 34, 35, };
	char mac_addr2[] = { 40, 41, 42, 43, 44, 45, };
	char mac_addr3[] = { 50, 51, 52, 53, 54, 55, };
	char mac_addr4[] = { 60, 61, 62, 63, 64, 65, };

	ret = odp_init_global(&instance, NULL, NULL);
	if (ret != 0) {
		ODPH_ERR("odp_shm_init_global fail\n");
		exit(EXIT_FAILURE);
	}
	ret = odp_init_local(instance, ODP_THREAD_WORKER);
	if (ret != 0) {
		ODPH_ERR("odp_shm_init_local fail\n");
		exit(EXIT_FAILURE);
	}

	printf("test hash table:\n");
	test_ops = &odph_hash_table_ops;

	table = test_ops->f_create("test", 2, sizeof(key1), sizeof(mac_addr1));
	if (table == NULL) {
		printf("table create fail\n");
		return -1;
	}
	ret += test_ops->f_put(table, &key1, mac_addr1);

	ret += test_ops->f_put(table, &key2, mac_addr2);

	ret += test_ops->f_put(table, &key3, mac_addr3);

	if (ret != 0) {
		printf("put value fail\n");
		return -1;
	}

	ret = test_ops->f_get(table, &key1, &tmp, 32);
	if (ret != 0) {
		printf("get value fail\n");
		return -1;
	}
	printf("\t1  get '123' tmp = %s,\n", tmp);

	ret = test_ops->f_put(table, &key1, mac_addr4);
	if (ret != 0) {
		printf("repeat put value fail\n");
		return -1;
	}

	ret = test_ops->f_get(table, &key1, &tmp, 32);
	if (ret != 0 || memcmp(tmp, mac_addr4, sizeof(mac_addr4)) != 0) {
		printf("get value fail\n");
		return -1;
	}

	printf("\t2  repeat get '123' value = %s\n", tmp);

	ret = test_ops->f_remove(table, &key1);
	if (ret != 0) {
		printf("remove value fail\n");
		return -1;
	}
	ret = test_ops->f_get(table, &key1, tmp, 32);
	if (ret == 0) {
		printf("remove value fail actually\n");
		return -1;
	}
	printf("\t3  remove success!\n");

	tmp_tbl = test_ops->f_lookup("test");
	if (tmp_tbl != table) {
		printf("lookup table fail!!!\n");
		return -1;
	}
	printf("\t4  lookup table success!\n");

	ret = test_ops->f_des(table);
	if (ret != 0) {
		printf("destroy table fail!!!\n");
		exit(EXIT_FAILURE);
	}
	printf("\t5  destroy table success!\n");

	printf("all test finished success!!\n");

	if (odp_term_local()) {
		ODPH_ERR("Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
