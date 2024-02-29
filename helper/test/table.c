/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_instance_t instance;
	int ret = 0;
	odph_table_t table;
	odph_table_t tmp_tbl;
	odph_table_ops_t *test_ops;
	char tmp[32];
	char key1[] = "1234";
	char key2[] = "1122";
	char key3[] = "3344";
	char value1[] = "0A1122334401";
	char value2[] = "0A1122334402";
	char value3[] = "0B4433221101";
	char value4[] = "0B4433221102";

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

	table = test_ops->f_create("test", 2, sizeof(key1), sizeof(value1));
	if (table == NULL) {
		printf("table create fail\n");
		return -1;
	}
	ret += test_ops->f_put(table, &key1, value1);

	ret += test_ops->f_put(table, &key2, value2);

	ret += test_ops->f_put(table, &key3, value3);

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

	ret = test_ops->f_put(table, &key1, value4);
	if (ret != 0) {
		printf("repeat put value fail\n");
		return -1;
	}

	ret = test_ops->f_get(table, &key1, &tmp, 32);
	if (ret != 0 || memcmp(tmp, value4, sizeof(value4)) != 0) {
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
