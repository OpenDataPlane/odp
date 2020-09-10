/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include <odp_api.h>

typedef struct test_global_t {
	int shm;
	int shm_all;
	int pool;
	int queue;

} test_global_t;

static test_global_t test_global;

static void print_usage(void)
{
	printf("This example prints out debug information on various ODP objects.\n"
	       "Select debug functions to be called with options. All listed functions\n"
	       "are called when no options are given.\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -S, --shm_all      Call odp_shm_print_all()\n"
	       "  -s, --shm          Create a SHM and call odp_shm_print()\n"
	       "  -p, --pool         Create various types of pools and call odp_pool_print()\n"
	       "  -q, --queue        Create various types of queues and call odp_queue_print()\n"
	       "  -h, --help         Display help and exit.\n\n");
}

static int parse_options(int argc, char *argv[], test_global_t *global)
{
	int opt, long_index;

	const struct option longopts[] = {
		{"shm_all",     no_argument,       NULL, 'S'},
		{"shm",         no_argument,       NULL, 's'},
		{"pool",        no_argument,       NULL, 'p'},
		{"queue",       no_argument,       NULL, 'q'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+Sspqh";
	int ret = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'S':
			global->shm_all = 1;
			break;
		case 's':
			global->shm = 1;
			break;
		case 'p':
			global->pool = 1;
			break;
		case 'q':
			global->queue = 1;
			break;
		case 'h':
		default:
			print_usage();
			return -1;
		}
	}

	return ret;
}

static int shm_debug(test_global_t *global)
{
	const char *name = "debug_shm";
	odp_shm_t shm = ODP_SHM_INVALID;

	if (global->shm) {
		shm = odp_shm_reserve(name, 8 * 1024, 64, 0);
		if (shm == ODP_SHM_INVALID) {
			printf("SHM reserve failed: %s\n", name);
			return -1;
		}
	}

	if (global->shm_all) {
		printf("\n");
		odp_shm_print_all();
	}

	if (global->shm) {
		printf("\n");
		odp_shm_print(shm);

		if (odp_shm_free(shm)) {
			printf("SHM free failed: %s\n", name);
			return -1;
		}
	}

	return 0;
}

static int buffer_debug(odp_pool_t pool)
{
	odp_buffer_t buf = odp_buffer_alloc(pool);

	if (buf == ODP_BUFFER_INVALID) {
		printf("Buffer alloc failed\n");
		return -1;
	}

	printf("\n");
	odp_buffer_print(buf);

	odp_buffer_free(buf);

	return 0;
}

static int packet_debug(odp_pool_t pool, int len)
{
	odp_packet_t pkt = odp_packet_alloc(pool, len);

	if (pkt == ODP_PACKET_INVALID) {
		printf("Packet alloc failed\n");
		return -1;
	}

	printf("\n");
	odp_packet_print(pkt);

	odp_packet_free(pkt);

	return 0;
}

static int pool_debug(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	const char *name;
	int pkt_len = 100;

	name = "debug_buffer_pool";
	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.num  = 10;
	param.buf.size = 1000;

	pool = odp_pool_create(name, &param);

	if (pool == ODP_POOL_INVALID) {
		printf("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (buffer_debug(pool))
		return -1;

	if (odp_pool_destroy(pool)) {
		printf("Pool destroy failed: %s\n", name);
		return -1;
	}

	name = "debug_packet_pool";
	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.pkt.num     = 10;
	param.pkt.len     = pkt_len;
	param.pkt.max_len = 1000;

	pool = odp_pool_create(name, &param);

	if (pool == ODP_POOL_INVALID) {
		printf("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (packet_debug(pool, pkt_len))
		return -1;

	if (odp_pool_destroy(pool)) {
		printf("Pool destroy failed: %s\n", name);
		return -1;
	}

	name = "debug_tmo_pool";
	odp_pool_param_init(&param);
	param.type = ODP_POOL_TIMEOUT;
	param.tmo.num = 10;

	pool = odp_pool_create(name, &param);

	if (pool == ODP_POOL_INVALID) {
		printf("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (odp_pool_destroy(pool)) {
		printf("Pool destroy failed: %s\n", name);
		return -1;
	}

	return 0;
}

static int queue_debug(void)
{
	odp_queue_t queue;
	odp_queue_param_t param;
	const char *name;

	name = "debug_plain_queue";
	odp_queue_param_init(&param);
	param.type = ODP_QUEUE_TYPE_PLAIN;

	queue = odp_queue_create(name, &param);

	if (queue == ODP_QUEUE_INVALID) {
		printf("Queue create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_queue_print(queue);

	if (odp_queue_destroy(queue)) {
		printf("Queue destroy failed: %s\n", name);
		return -1;
	}

	/* Configure scheduler before creating any scheduled queues */
	if (odp_schedule_config(NULL)) {
		printf("Schedule config failed\n");
		return -1;
	}

	name = "debug_sched_queue";
	odp_queue_param_init(&param);
	param.type = ODP_QUEUE_TYPE_SCHED;

	queue = odp_queue_create(name, &param);

	if (queue == ODP_QUEUE_INVALID) {
		printf("Queue create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_queue_print(queue);

	if (odp_queue_destroy(queue)) {
		printf("Queue destroy failed: %s\n", name);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	odp_instance_t inst;
	test_global_t *global = &test_global;

	printf("ODP debug example\n\n");
	memset(global, 0, sizeof(test_global_t));

	if (argc < 2) {
		/* If not arguments, run all test cases */
		global->shm_all = 1;
		global->shm     = 1;
		global->pool    = 1;
		global->queue   = 1;
	} else {
		if (parse_options(argc, argv, global))
			return -1;
	}

	if (odp_init_global(&inst, NULL, NULL)) {
		printf("Global init failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		printf("Local init failed.\n");
		return -1;
	}

	odp_sys_info_print();

	if ((global->shm_all || global->shm) && shm_debug(global)) {
		printf("SHM debug failed.\n");
		return -1;
	}

	if (global->pool && pool_debug()) {
		printf("Pool debug failed.\n");
		return -1;
	}

	if (global->queue && queue_debug()) {
		printf("Queue debug failed.\n");
		return -1;
	}

	if (odp_term_local()) {
		printf("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		printf("Global term failed.\n");
		return -1;
	}

	return 0;
}
