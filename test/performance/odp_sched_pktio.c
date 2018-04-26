/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define MAX_WORKERS       64
#define MAX_PKTIOS        32
#define MAX_PKTIO_NAME    31
#define MAX_PKTIO_QUEUES  MAX_WORKERS
#define MAX_PKT_LEN       1514
#define MAX_PKT_NUM       (16 * 1024)
#define MIN_PKT_SEG_LEN   64
#define BURST_SIZE        32
#define CHECK_PERIOD      10000
#define MAX_PKTIO_INDEXES 256
#define TEST_PASSED_LIMIT 5000

typedef struct {
	int  worker_id;
	void *test_global_ptr;
} worker_arg_t;

typedef struct ODP_ALIGNED_CACHE {
	uint64_t rx_pkt;
	uint64_t tx_pkt;
} worker_stat_t;

typedef struct {
	volatile int  stop_workers;
	odp_barrier_t worker_start;

	struct {
		int num_worker;
		int num_pktio;
		int num_pktio_queue;
		uint8_t collect_stat;
	} opt;

	int max_workers;
	odp_cpumask_t cpumask;
	odp_instance_t instance;

	int worker_cpu[MAX_WORKERS];

	odp_pool_t pool;
	uint32_t   pkt_len;
	uint32_t   pkt_num;

	struct {
		char name[MAX_PKTIO_NAME + 1];
		odp_pktio_t pktio;
		int pktio_index;
		int started;
		odph_ethaddr_t my_addr;
		odp_queue_t input_queue[MAX_PKTIO_QUEUES];
		odp_pktout_queue_t pktout[MAX_PKTIO_QUEUES];

	} pktio[MAX_PKTIOS];

	worker_arg_t worker_arg[MAX_WORKERS];

	/* Maps pktio input index to pktio[] index for output */
	uint8_t pktio_map[MAX_PKTIO_INDEXES];

	worker_stat_t worker_stat[MAX_WORKERS];
	uint64_t rx_pkt_sum;
	uint64_t tx_pkt_sum;

} test_global_t;

static test_global_t *test_global;

static inline void set_dst_eth_addr(odph_ethaddr_t *eth_addr, int index)
{
	eth_addr->addr[0] = 0x02;
	eth_addr->addr[1] = 0;
	eth_addr->addr[2] = 0;
	eth_addr->addr[3] = 0;
	eth_addr->addr[4] = 0;
	eth_addr->addr[5] = index;
}

static inline void fill_eth_addr(odp_packet_t pkt[], int num,
				 test_global_t *test_global, int out)
{
	odph_ethhdr_t *eth;
	int i;

	for (i = 0; i < num; ++i) {
		eth = odp_packet_data(pkt[i]);

		eth->src = test_global->pktio[out].my_addr;
		set_dst_eth_addr(&eth->dst, out);
	}
}

static int worker_thread(void *arg)
{
	odp_event_t ev[BURST_SIZE];
	int num, sent, drop, in, out;
	odp_pktout_queue_t pktout;
	worker_arg_t *worker_arg = arg;
	test_global_t *test_global = worker_arg->test_global_ptr;
	int worker_id = worker_arg->worker_id;
	uint32_t polls = 0;

	printf("Worker %i started\n", worker_id);

	/* Wait for other workers to start */
	odp_barrier_wait(&test_global->worker_start);

	while (1) {
		odp_packet_t pkt[BURST_SIZE];

		num = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
					 ev, BURST_SIZE);

		polls++;

		if (polls == CHECK_PERIOD) {
			polls = 0;
			if (test_global->stop_workers)
				break;
		}

		if (num <= 0)
			continue;

		odp_packet_from_event_multi(pkt, ev, num);

		in     = odp_packet_input_index(pkt[0]);
		out    = test_global->pktio_map[in];
		pktout = test_global->pktio[out].pktout[worker_id];

		fill_eth_addr(pkt, num, test_global, out);

		sent = odp_pktout_send(pktout, pkt, num);

		if (odp_unlikely(sent < 0))
			sent = 0;

		drop = num - sent;

		if (odp_unlikely(drop))
			odp_packet_free_multi(&pkt[sent], drop);

		if (odp_unlikely(test_global->opt.collect_stat)) {
			test_global->worker_stat[worker_id].rx_pkt += num;
			test_global->worker_stat[worker_id].tx_pkt += sent;
		}
	}

	printf("Worker %i stopped\n", worker_id);

	return 0;
}

static void sig_handler(int signo)
{
	(void)signo;

	if (test_global) {
		test_global->stop_workers = 1;
		odp_mb_full();
	}
}

/* Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))

static void print_usage(const char *progname)
{
	printf("\n"
	       "Scheduler with packet IO test application.\n"
	       "\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -i, --interface <name>   Packet IO interfaces (comma-separated, no spaces)\n"
	       "  -c, --num_cpu <number>   Worker thread count. Default: 1\n"
	       "  -q, --num_queue <number> Number of pktio queues. Default: Worker thread count\n"
	       "  -s, --stat               Collect statistics.\n"
	       "  -h, --help               Display help and exit.\n\n",
	       NO_PATH(progname));
}

static int parse_options(int argc, char *argv[], test_global_t *test_global)
{
	int i, opt, long_index;
	char *name, *str;
	int len, str_len;
	const struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},
		{"num_cpu",   required_argument, NULL, 'c'},
		{"num_queue", required_argument, NULL, 'q'},
		{"stat",      no_argument,       NULL, 's'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+i:c:q:sh";
	int ret = 0;

	test_global->opt.num_worker = 1;
	test_global->opt.num_pktio_queue = 0;

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':
			i = 0;
			str = optarg;
			str_len = strlen(str);

			while (str_len > 0) {
				len = strcspn(str, ",");
				str_len -= len + 1;

				if (i == MAX_PKTIOS) {
					printf("Error: Too many interfaces\n");
					ret = -1;
					break;
				}

				if (len > MAX_PKTIO_NAME) {
					printf("Error: Too long interface name %s\n",
					       str);
					ret = -1;
					break;
				}

				name = test_global->pktio[i].name;
				memcpy(name, str, len);
				str += len + 1;
				i++;
			}

			test_global->opt.num_pktio = i;

			break;
		case 'c':
			test_global->opt.num_worker = atoi(optarg);
			break;
		case 'q':
			test_global->opt.num_pktio_queue = atoi(optarg);
			break;
		case 's':
			test_global->opt.collect_stat = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			ret = -1;
			break;
		default:
			ret = -1;
			break;
		}
	}

	if (test_global->opt.num_pktio_queue == 0)
		test_global->opt.num_pktio_queue = test_global->opt.num_worker;

	return ret;
}

static int config_setup(test_global_t *test_global)
{
	int i, cpu;
	odp_pool_capability_t pool_capa;
	uint32_t pkt_len, pkt_num;
	odp_cpumask_t *cpumask = &test_global->cpumask;

	test_global->max_workers = odp_cpumask_default_worker(cpumask, 0);

	if (test_global->opt.num_worker > test_global->max_workers ||
	    test_global->opt.num_worker > MAX_WORKERS) {
		printf("Error: Too many workers %i.\n",
		       test_global->opt.num_worker);
		return -1;
	}

	cpu = odp_cpumask_first(cpumask);
	for (i = 0; i < test_global->opt.num_worker; ++i) {
		test_global->worker_cpu[i] = cpu;
		cpu = odp_cpumask_next(cpumask, cpu);
	}

	if (test_global->opt.num_pktio == 0) {
		printf("Error: At least one pktio interface needed.\n");
		return -1;
	}

	if (MAX_PKTIO_INDEXES <= odp_pktio_max_index()) {
		printf("Error: Larger pktio_map[] table needed: %u\n",
		       odp_pktio_max_index());
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capability failed.\n");
		return -1;
	}

	pkt_len = MAX_PKT_LEN;
	pkt_num = MAX_PKT_NUM;

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len)
		pkt_len = pool_capa.pkt.max_len;

	if (pool_capa.pkt.max_num && pkt_num > pool_capa.pkt.max_num)
		pkt_num = pool_capa.pkt.max_num;

	test_global->pkt_len = pkt_len;
	test_global->pkt_num = pkt_num;

	return 0;
}

static void print_config(test_global_t *test_global)
{
	char cpumask_str[ODP_CPUMASK_STR_SIZE];
	int i;

	odp_cpumask_to_str(&test_global->cpumask, cpumask_str,
			   ODP_CPUMASK_STR_SIZE);

	printf("\n"
	       "Test configuration:\n"
	       "  max workers:           %i\n"
	       "  available worker cpus: %s\n"
	       "  num workers:           %i\n"
	       "  worker cpus:          ",
	       test_global->max_workers,
	       cpumask_str,
	       test_global->opt.num_worker);

	for (i = 0; i < test_global->opt.num_worker; i++)
		printf(" %i", test_global->worker_cpu[i]);

	printf("\n"
	       "  num interfaces:        %i\n"
	       "  interface names:      ", test_global->opt.num_pktio);

	for (i = 0; i < test_global->opt.num_pktio; i++)
		printf(" %s", test_global->pktio[i].name);

	printf("\n"
	       "  queues per interface:  %i\n",
	       test_global->opt.num_pktio_queue);

	printf("  collect statistics:    %u\n", test_global->opt.collect_stat);

	printf("\n");
}

static void print_stat(test_global_t *test_global, uint64_t nsec)
{
	int i;
	uint64_t rx, tx, drop;
	uint64_t rx_sum = 0;
	uint64_t tx_sum = 0;
	double sec = 0.0;

	printf("\nTest statistics\n");
	printf("  worker           rx_pkt           tx_pkt          dropped\n");

	for (i = 0; i < test_global->opt.num_worker; i++) {
		rx = test_global->worker_stat[i].rx_pkt;
		tx = test_global->worker_stat[i].tx_pkt;
		rx_sum += rx;
		tx_sum += tx;

		printf("  %6i %16" PRIu64 " %16" PRIu64 " %16" PRIu64 "\n",
		       i, rx, tx, rx - tx);
	}

	test_global->rx_pkt_sum = rx_sum;
	test_global->tx_pkt_sum = tx_sum;
	drop = rx_sum - tx_sum;

	printf("         --------------------------------------------------\n");
	printf("  total  %16" PRIu64 " %16" PRIu64 " %16" PRIu64 "\n\n",
	       rx_sum, tx_sum, drop);

	sec = nsec / 1000000000.0;
	printf("  Total test time: %.2f sec\n", sec);
	printf("  Rx packet rate:  %.2f pps\n", rx_sum / sec);
	printf("  Tx packet rate:  %.2f pps\n", tx_sum / sec);
	printf("  Drop rate:       %.2f pps\n\n", drop / sec);
}

static int open_pktios(test_global_t *test_global)
{
	odp_pool_param_t  pool_param;
	odp_pktio_param_t pktio_param;
	odp_pool_t pool;
	odp_pktio_t pktio;
	odp_pktio_capability_t pktio_capa;
	odp_pktio_config_t pktio_config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_schedule_sync_t sched_sync;
	unsigned int num_queue;
	char *name;
	int i, num_pktio, ret;

	num_pktio = test_global->opt.num_pktio;
	num_queue = test_global->opt.num_pktio_queue;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.seg_len = MIN_PKT_SEG_LEN;
	pool_param.pkt.len     = test_global->pkt_len;
	pool_param.pkt.num     = test_global->pkt_num;
	pool_param.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &pool_param);

	test_global->pool = pool;

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create.\n");
		return -1;
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode  = ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	sched_sync = ODP_SCHED_SYNC_ATOMIC;

	for (i = 0; i < num_pktio; i++)
		test_global->pktio[i].pktio = ODP_PKTIO_INVALID;

	/* Open and configure interfaces */
	for (i = 0; i < num_pktio; i++) {
		name  = test_global->pktio[i].name;
		pktio = odp_pktio_open(name, pool, &pktio_param);

		if (pktio == ODP_PKTIO_INVALID) {
			printf("Error (%s): Pktio open failed.\n", name);
			return -1;
		}

		test_global->pktio[i].pktio = pktio;
		test_global->pktio[i].pktio_index = odp_pktio_index(pktio);

		ret = odp_pktio_mac_addr(pktio,
					 test_global->pktio[i].my_addr.addr,
					 ODPH_ETHADDR_LEN);
		if (ret != ODPH_ETHADDR_LEN) {
			printf("Error (%s): Bad MAC address len.\n", name);
			return -1;
		}

		odp_pktio_print(pktio);

		if (odp_pktio_capability(pktio, &pktio_capa)) {
			printf("Error (%s): Pktio capa failed.\n", name);
			return -1;
		}

		if (num_queue > pktio_capa.max_input_queues) {
			printf("Error (%s): Too many input queues: %u\n",
			       name, num_queue);
			return -1;
		}

		if (num_queue > pktio_capa.max_output_queues) {
			printf("Error (%s): Too many output queues: %u\n",
			       name, num_queue);
			return -1;
		}

		odp_pktio_config_init(&pktio_config);
		pktio_config.parser.layer = ODP_PROTO_LAYER_NONE;

		odp_pktio_config(pktio, &pktio_config);

		odp_pktin_queue_param_init(&pktin_param);

		pktin_param.queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		pktin_param.queue_param.sched.sync  = sched_sync;
		pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;

		if (num_queue > 1) {
			pktin_param.hash_enable = 1;
			pktin_param.hash_proto.proto.ipv4_udp = 1;
		}

		pktin_param.num_queues = num_queue;

		if (odp_pktin_queue_config(pktio, &pktin_param)) {
			printf("Error (%s): Pktin config failed.\n", name);
			return -1;
		}

		if (odp_pktin_event_queue(pktio,
					  test_global->pktio[i].input_queue,
					  num_queue) != (int)num_queue) {
			printf("Error (%s): Input queue query failed.\n", name);
			return -1;
		}

		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.num_queues  = num_queue;
		pktout_param.op_mode     = ODP_PKTIO_OP_MT_UNSAFE;

		if (odp_pktout_queue_config(pktio, &pktout_param)) {
			printf("Error (%s): Pktout config failed.\n", name);
			return -1;
		}

		if (odp_pktout_queue(pktio,
				     test_global->pktio[i].pktout,
				     num_queue) != (int)num_queue) {
			printf("Error (%s): Output queue query failed.\n",
			       name);
			return -1;
		}
	}

	return 0;
}

static void link_pktios(test_global_t *test_global)
{
	int i, num_pktio, input, output;

	num_pktio = test_global->opt.num_pktio;

	printf("Forwarding table (pktio indexes)\n");

	/* If single interface loopback, otherwise forward to the next
	 * interface. */
	for (i = 0; i < num_pktio; i++) {
		input  = test_global->pktio[i].pktio_index;
		output = (i + 1) % num_pktio;
		test_global->pktio_map[input] = output;
		printf("  input %i, output %i\n",
		       input,
		       test_global->pktio[output].pktio_index);
	}

	printf("\n");
}

static int start_pktios(test_global_t *test_global)
{
	int i;

	for (i = 0; i < test_global->opt.num_pktio; i++) {
		if (odp_pktio_start(test_global->pktio[i].pktio)) {
			printf("Error (%s): Pktio start failed.\n",
			       test_global->pktio[i].name);

			return -1;
		}

		test_global->pktio[i].started = 1;
	}

	return 0;
}

static int stop_pktios(test_global_t *test_global)
{
	odp_pktio_t pktio;
	int i, ret = 0;

	for (i = 0; i < test_global->opt.num_pktio; i++) {
		pktio = test_global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID ||
		    test_global->pktio[i].started == 0)
			continue;

		if (odp_pktio_stop(pktio)) {
			printf("Error (%s): Pktio stop failed.\n",
			       test_global->pktio[i].name);
			ret = -1;
		}
	}

	return ret;
}

static void empty_queues(void)
{
	odp_event_t ev;
	uint64_t wait_time = odp_schedule_wait_time(ODP_TIME_SEC_IN_NS / 2);

	/* Drop all events from all queues */
	while (1) {
		ev = odp_schedule(NULL, wait_time);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}
}

static int close_pktios(test_global_t *test_global)
{
	odp_pktio_t pktio;
	odp_pool_t pool;
	int i, ret = 0;

	for (i = 0; i < test_global->opt.num_pktio; i++) {
		pktio = test_global->pktio[i].pktio;

		if (pktio == ODP_PKTIO_INVALID)
			continue;

		if (odp_pktio_close(pktio)) {
			printf("Error (%s): Pktio close failed.\n",
			       test_global->pktio[i].name);
			ret = -1;
		}
	}

	pool = test_global->pool;

	if (pool == ODP_POOL_INVALID)
		return ret;

	if (odp_pool_destroy(pool)) {
		printf("Error: Pool destroy failed.\n");
		ret = -1;
	}

	return ret;
}

static void start_workers(odph_odpthread_t thread[],
			  test_global_t *test_global)
{
	int i;
	odp_cpumask_t cpumask;
	odph_odpthread_params_t param;
	int num = test_global->opt.num_worker;

	memset(&param, 0, sizeof(odph_odpthread_params_t));
	param.start    = worker_thread;
	param.thr_type = ODP_THREAD_WORKER;
	param.instance = test_global->instance;

	memset(thread, 0, num * sizeof(odph_odpthread_t));

	for (i = 0; i < num; i++) {
		odp_cpumask_zero(&cpumask);
		odp_cpumask_set(&cpumask, test_global->worker_cpu[i]);
		test_global->worker_arg[i].worker_id = i;
		test_global->worker_arg[i].test_global_ptr = test_global;
		param.arg = &test_global->worker_arg[i];

		odph_odpthreads_create(&thread[i], &cpumask, &param);
	}
}

static void wait_workers(odph_odpthread_t thread[], test_global_t *test_global)
{
	int i;

	for (i = 0; i < test_global->opt.num_worker; ++i)
		odph_odpthreads_join(&thread[i]);
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	odp_time_t t1, t2;
	odph_odpthread_t thread[MAX_WORKERS];
	int ret = 0;

	signal(SIGINT, sig_handler);

	/* List features not to be used (may optimize performance) */
	odp_init_param_init(&init);
	init.not_used.feat.cls    = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec  = 1;
	init.not_used.feat.timer  = 1;
	init.not_used.feat.tm     = 1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("test_global", sizeof(test_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		printf("Error: shm reserve failed.\n");
		return -1;
	}

	test_global = odp_shm_addr(shm);
	memset(test_global, 0, sizeof(test_global_t));

	test_global->instance = instance;
	test_global->pool     = ODP_POOL_INVALID;

	if (parse_options(argc, argv, test_global))
		goto quit;

	odp_sys_info_print();

	if (config_setup(test_global))
		goto quit;

	print_config(test_global);

	if (open_pktios(test_global))
		goto quit;

	link_pktios(test_global);

	odp_barrier_init(&test_global->worker_start,
			 test_global->opt.num_worker + 1);

	start_workers(thread, test_global);

	/* Synchronize pktio configuration with workers. Worker are now ready
	 * to process packets. */
	odp_barrier_wait(&test_global->worker_start);

	if (start_pktios(test_global)) {
		test_global->stop_workers = 1;
		odp_mb_full();
	}

	t1 = odp_time_local();

	wait_workers(thread, test_global);

	t2 = odp_time_local();

quit:
	stop_pktios(test_global);
	empty_queues();
	close_pktios(test_global);

	if (test_global->opt.collect_stat) {
		print_stat(test_global, odp_time_diff_ns(t2, t1));

		/* Encode return value for validation test usage. */
		if (test_global->rx_pkt_sum > TEST_PASSED_LIMIT)
			ret += 1;

		if (test_global->tx_pkt_sum > TEST_PASSED_LIMIT)
			ret += 2;
	}

	if (odp_shm_free(shm)) {
		printf("Error: shm free failed.\n");
		return -1;
	}

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		return -1;
	}

	return ret;
}
