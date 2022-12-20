/* Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

typedef struct test_global_t {
	int system;
	int shm;
	int pool;
	int queue;
	int pktio;
	int ipsec;
	int timer;
	int stash;

} test_global_t;

static test_global_t test_global;

static void print_usage(void)
{
	printf("This example prints out debug information on various ODP objects.\n"
	       "Select debug functions to be called with options. All listed functions\n"
	       "are called when no options are given.\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -S, --system       Call odp_sys_info_print() and odp_sys_config_print()\n"
	       "  -s, --shm          Create a SHM and call odp_shm_print()\n"
	       "  -p, --pool         Create various types of pools and call odp_pool_print()\n"
	       "  -q, --queue        Create various types of queues and call odp_queue_print()\n"
	       "  -i, --interface    Create packet IO interface (loop) and call odp_pktio_print()\n"
	       "  -I, --ipsec        Call odp_ipsec_print()\n"
	       "  -t, --timer        Call timer pool, timer and timeout print functions\n"
	       "  -a, --stash        Create stash and call odp_stash_print()\n"
	       "  -h, --help         Display help and exit.\n\n");
}

static int parse_options(int argc, char *argv[], test_global_t *global)
{
	int opt, long_index;

	const struct option longopts[] = {
		{"system",      no_argument,       NULL, 'S'},
		{"shm",         no_argument,       NULL, 's'},
		{"pool",        no_argument,       NULL, 'p'},
		{"queue",       no_argument,       NULL, 'q'},
		{"interface",   no_argument,       NULL, 'i'},
		{"ipsec",       no_argument,       NULL, 'I'},
		{"timer",       no_argument,       NULL, 't'},
		{"stash",       no_argument,       NULL, 'a'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+SspqiItah";
	int ret = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'S':
			global->system = 1;
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
		case 'i':
			global->pktio = 1;
			break;
		case 'I':
			global->ipsec = 1;
			break;
		case 't':
			global->timer = 1;
			break;
		case 'a':
			global->stash = 1;
			break;
		case 'h':
		default:
			print_usage();
			return -1;
		}
	}

	return ret;
}

static int shm_debug(void)
{
	const char *name = "debug_shm";
	odp_shm_t shm = ODP_SHM_INVALID;

	shm = odp_shm_reserve(name, 8 * 1024, 64, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_shm_print_all();

	printf("\n");
	odp_shm_print(shm);

	if (odp_shm_free(shm)) {
		ODPH_ERR("SHM free failed: %s\n", name);
		return -1;
	}

	return 0;
}

static int buffer_debug(odp_pool_t pool)
{
	odp_buffer_t buf = odp_buffer_alloc(pool);

	if (buf == ODP_BUFFER_INVALID) {
		ODPH_ERR("Buffer alloc failed\n");
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
		ODPH_ERR("Packet alloc failed\n");
		return -1;
	}

	printf("\n");
	odp_packet_print(pkt);

	printf("\n");
	odp_packet_print_data(pkt, 0, len);

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
		ODPH_ERR("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (buffer_debug(pool))
		return -1;

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed: %s\n", name);
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
		ODPH_ERR("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (packet_debug(pool, pkt_len))
		return -1;

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed: %s\n", name);
		return -1;
	}

	name = "debug_tmo_pool";
	odp_pool_param_init(&param);
	param.type = ODP_POOL_TIMEOUT;
	param.tmo.num = 10;

	pool = odp_pool_create(name, &param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_pool_print(pool);

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed: %s\n", name);
		return -1;
	}

	return 0;
}

static int queue_debug(void)
{
	odp_queue_param_t param;
	const char *name;
	int i;
	int num = 3;
	odp_queue_t queue[num];

	name = "plain_queue";
	odp_queue_param_init(&param);
	param.type = ODP_QUEUE_TYPE_PLAIN;

	queue[0] = odp_queue_create(name, &param);

	if (queue[0] == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_queue_print(queue[0]);

	name = "parallel_sched_queue";
	odp_queue_param_init(&param);
	param.type = ODP_QUEUE_TYPE_SCHED;

	queue[1] = odp_queue_create(name, &param);

	if (queue[1] == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_queue_print(queue[1]);

	name = "atomic_sched_queue";
	param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	param.sched.prio = odp_schedule_max_prio();

	queue[2] = odp_queue_create(name, &param);

	if (queue[2] == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed: %s\n", name);
		return -1;
	}

	printf("\n");
	odp_queue_print(queue[2]);

	printf("\n");
	odp_queue_print_all();

	printf("\n");
	odp_schedule_print();

	for (i = 0; i < num; i++) {
		if (odp_queue_destroy(queue[i])) {
			ODPH_ERR("Queue destroy failed: %i\n", i);
			return -1;
		}
	}

	return 0;
}

static int pktio_debug(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_pktio_t pktio;
	int pkt_len = 100;

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_PACKET;
	pool_param.pkt.num = 10;
	pool_param.pkt.len = pkt_len;

	pool = odp_pool_create("debug_pktio_pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed\n");
		return -1;
	}

	pktio = odp_pktio_open("loop", pool, NULL);

	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Pktio open failed\n");
		return -1;
	}

	printf("\n");
	odp_pktio_print(pktio);

	if (odp_pktio_close(pktio)) {
		ODPH_ERR("Pktio close failed\n");
		return -1;
	}

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed\n");
		return -1;
	}

	return 0;
}

static int ipsec_debug(void)
{
	printf("\n");
	odp_ipsec_print();

	return 0;
}

static int timer_debug(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_timeout_t timeout;
	odp_timer_res_capability_t timer_res_capa;
	odp_timer_capability_t timer_capa;
	odp_timer_pool_t timer_pool;
	odp_timer_pool_param_t timer_param;
	odp_timer_start_t start_param;
	odp_timer_t timer;
	odp_queue_t queue;
	odp_queue_param_t queue_param;
	odp_event_t event;
	uint64_t tick;
	uint64_t max_tmo = ODP_TIME_SEC_IN_NS;
	uint64_t res     = 100 * ODP_TIME_MSEC_IN_NS;

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = 10;

	pool = odp_pool_create("debug_timer", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed\n");
		return -1;
	}

	timeout = odp_timeout_alloc(pool);
	if (timeout == ODP_TIMEOUT_INVALID) {
		ODPH_ERR("Timeout alloc failed\n");
		return -1;
	}

	if (odp_timer_capability(ODP_CLOCK_DEFAULT, &timer_capa)) {
		ODPH_ERR("Timer capa failed\n");
		return -1;
	}

	if (timer_capa.max_tmo.max_tmo < max_tmo)
		max_tmo = timer_capa.max_tmo.max_tmo;

	memset(&timer_res_capa, 0, sizeof(odp_timer_res_capability_t));
	timer_res_capa.max_tmo = max_tmo;
	if (odp_timer_res_capability(ODP_CLOCK_DEFAULT, &timer_res_capa)) {
		ODPH_ERR("Timer resolution capability failed\n");
		return -1;
	}

	if (timer_res_capa.res_ns > res)
		res = timer_res_capa.res_ns;

	odp_timer_pool_param_init(&timer_param);
	timer_param.res_ns  = res;
	timer_param.min_tmo = max_tmo / 10;
	timer_param.max_tmo = max_tmo;
	timer_param.num_timers = 10;
	timer_param.clk_src = ODP_CLOCK_DEFAULT;

	timer_pool = odp_timer_pool_create("debug_timer", &timer_param);

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Timer pool create failed\n");
		return -1;
	}

	odp_timer_pool_start();

	odp_queue_param_init(&queue_param);
	if (timer_capa.queue_type_sched)
		queue_param.type = ODP_QUEUE_TYPE_SCHED;

	queue = odp_queue_create("debug_timer", &queue_param);
	if (queue == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed.\n");
		return -1;
	}

	printf("\n");
	odp_timer_pool_print(timer_pool);

	tick = odp_timer_ns_to_tick(timer_pool, max_tmo / 2);

	timer = odp_timer_alloc(timer_pool, queue, (void *)(uintptr_t)0xdeadbeef);

	printf("\n");
	odp_timeout_print(timeout);

	event = odp_timeout_to_event(timeout);

	start_param.tick_type = ODP_TIMER_TICK_REL;
	start_param.tick = tick;
	start_param.tmo_ev = event;

	if (odp_timer_start(timer, &start_param) != ODP_TIMER_SUCCESS)
		ODPH_ERR("Timer start failed.\n");

	printf("\n");
	odp_timer_print(timer);

	event = odp_timer_free(timer);

	if (event == ODP_EVENT_INVALID) {
		ODPH_ERR("Timer free failed.\n");
	} else {
		timeout = odp_timeout_from_event(event);

		printf("\n");
		odp_timeout_print(timeout);

		odp_timeout_free(timeout);
	}

	odp_timer_pool_destroy(timer_pool);

	if (odp_queue_destroy(queue)) {
		ODPH_ERR("Queue destroy failed\n");
		return -1;
	}

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed\n");
		return -1;
	}

	return 0;
}

static int stash_debug(void)
{
	odp_stash_param_t param;
	odp_stash_t stash;
	uint32_t val = 0xdeadbeef;

	odp_stash_param_init(&param);
	param.num_obj  = 10;
	param.obj_size = 4;

	stash = odp_stash_create("debug_stash", &param);

	if (stash == ODP_STASH_INVALID) {
		ODPH_ERR("Stash create failed\n");
		return -1;
	}

	if (odp_stash_put_u32(stash, &val, 1) != 1) {
		ODPH_ERR("Stash put failed\n");
		return -1;
	}

	printf("\n");
	odp_stash_print(stash);

	if (odp_stash_get_u32(stash, &val, 1) != 1) {
		ODPH_ERR("Stash get failed\n");
		return -1;
	}

	if (odp_stash_destroy(stash)) {
		ODPH_ERR("Stash destroy failed\n");
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
		global->system  = 1;
		global->shm     = 1;
		global->pool    = 1;
		global->queue   = 1;
		global->pktio   = 1;
		global->ipsec   = 1;
		global->timer   = 1;
		global->stash   = 1;
	} else {
		if (parse_options(argc, argv, global))
			exit(EXIT_FAILURE);
	}

	if (odp_init_global(&inst, NULL, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Configure scheduler before creating any scheduled queues */
	if (odp_schedule_config(NULL)) {
		ODPH_ERR("Schedule config failed\n");
		exit(EXIT_FAILURE);
	}

	if (global->system) {
		printf("\n");
		odp_sys_info_print();

		printf("\n");
		odp_sys_config_print();
	}

	if (global->shm && shm_debug()) {
		ODPH_ERR("SHM debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->pool && pool_debug()) {
		ODPH_ERR("Pool debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->queue && queue_debug()) {
		ODPH_ERR("Queue debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->pktio && pktio_debug()) {
		ODPH_ERR("Packet debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->ipsec && ipsec_debug()) {
		ODPH_ERR("IPSEC debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->timer && timer_debug()) {
		ODPH_ERR("Timer debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (global->stash && stash_debug()) {
		ODPH_ERR("Stash debug failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
