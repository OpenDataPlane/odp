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

#define DEBUG_PRINT       0
#define MAX_WORKERS       64
#define MAX_PKTIOS        32
#define MAX_PKTIO_NAME    31
#define MAX_PKTIO_QUEUES  MAX_WORKERS
#define MAX_PIPE_STAGES   64
#define MAX_PIPE_QUEUES   1024
#define MAX_PKT_LEN       1514
#define MAX_PKT_NUM       (128 * 1024)
#define MIN_PKT_SEG_LEN   64
#define CHECK_PERIOD      10000
#define TEST_PASSED_LIMIT 5000
#define TIMEOUT_OFFSET_NS 1000000
#define SCHED_MODE_PARAL  1
#define SCHED_MODE_ATOMIC 2
#define SCHED_MODE_ORDER  3

typedef struct test_options_t {
	long int timeout_us;
	int sched_mode;
	int num_worker;
	int num_pktio;
	int num_pktio_queue;
	int burst_size;
	int pipe_stages;
	int pipe_queues;
	uint32_t pipe_queue_size;
	uint8_t collect_stat;
	char pktio_name[MAX_PKTIOS][MAX_PKTIO_NAME + 1];

} test_options_t;

typedef struct {
	int  worker_id;
	void *test_global_ptr;
} worker_arg_t;

typedef struct ODP_ALIGNED_CACHE {
	uint64_t rx_pkt;
	uint64_t tx_pkt;
	uint64_t pipe_pkt;
	uint64_t tx_drop;
	uint64_t pipe_drop;
	uint64_t tmo;
} worker_stat_t;

typedef struct pktin_queue_context_t {
	/* Queue context must start with stage and idx */
	uint16_t stage;
	uint16_t queue_idx;

	uint8_t  dst_pktio;
	uint8_t  dst_queue;
	uint8_t  src_pktio;
	uint8_t  src_queue;
	odp_pktout_queue_t dst_pktout;
} pktin_queue_context_t;

typedef struct pipe_queue_context_t {
	/* Queue context must start with stage and idx. */
	uint16_t stage;
	uint16_t queue_idx;
} pipe_queue_context_t;

typedef struct {
	volatile int  stop_workers;
	odp_barrier_t worker_start;

	test_options_t opt;

	int max_workers;
	odp_cpumask_t cpumask;
	odp_instance_t instance;

	int worker_cpu[MAX_WORKERS];

	odp_pool_t pool;
	uint32_t   pkt_len;
	uint32_t   pkt_num;

	struct {
		odp_pktio_t pktio;
		int pktio_index;
		int started;
		odph_ethaddr_t my_addr;
		odp_queue_t input_queue[MAX_PKTIO_QUEUES];
		odp_pktout_queue_t pktout[MAX_PKTIO_QUEUES];
		pktin_queue_context_t queue_context[MAX_PKTIO_QUEUES];

	} pktio[MAX_PKTIOS];

	struct {
		odp_timer_pool_t timer_pool;
		odp_pool_t       timeout_pool;
		uint64_t         timeout_tick;
		odp_timer_t      timer[MAX_PKTIOS][MAX_PKTIO_QUEUES];

	} timer;

	struct {
		odp_queue_t queue[MAX_PIPE_QUEUES];
	} pipe_queue[MAX_PKTIOS][MAX_PIPE_STAGES];

	struct {
		pipe_queue_context_t ctx;
	} pipe_queue_ctx[MAX_PIPE_STAGES][MAX_PIPE_QUEUES];

	worker_arg_t worker_arg[MAX_WORKERS];

	worker_stat_t worker_stat[MAX_WORKERS];
	uint64_t rx_pkt_sum;
	uint64_t tx_pkt_sum;

	odp_schedule_config_t schedule_config;

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

static inline void send_packets(test_global_t *test_global,
				odp_packet_t pkt[], int num_pkt,
				int output, odp_pktout_queue_t pktout,
				int worker_id)
{
	int sent, drop;

	fill_eth_addr(pkt, num_pkt, test_global, output);

	sent = odp_pktout_send(pktout, pkt, num_pkt);

	if (odp_unlikely(sent < 0))
		sent = 0;

	drop = num_pkt - sent;

	if (odp_unlikely(drop))
		odp_packet_free_multi(&pkt[sent], drop);

	if (odp_unlikely(test_global->opt.collect_stat)) {
		test_global->worker_stat[worker_id].tx_pkt += sent;
		test_global->worker_stat[worker_id].tx_drop += drop;
	}
}

static int worker_thread_direct(void *arg)
{
	int num_pkt, out;
	odp_pktout_queue_t pktout;
	odp_queue_t queue;
	pktin_queue_context_t *queue_context;
	worker_arg_t *worker_arg = arg;
	test_global_t *test_global = worker_arg->test_global_ptr;
	int worker_id = worker_arg->worker_id;
	uint32_t polls = 0;
	int burst_size = test_global->opt.burst_size;

	printf("Worker %i started\n", worker_id);

	/* Wait for other workers to start */
	odp_barrier_wait(&test_global->worker_start);

	while (1) {
		odp_event_t ev[burst_size];
		odp_packet_t pkt[burst_size];

		num_pkt = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					     ev, burst_size);

		polls++;

		if (polls == CHECK_PERIOD) {
			polls = 0;
			if (test_global->stop_workers)
				break;
		}

		if (num_pkt <= 0)
			continue;

		queue_context = odp_queue_context(queue);

		if (DEBUG_PRINT)
			printf("worker %i: [%i/%i] -> [%i/%i], %i packets\n",
			       worker_id,
			       queue_context->src_pktio,
			       queue_context->src_queue,
			       queue_context->dst_pktio,
			       queue_context->dst_queue, num_pkt);

		odp_packet_from_event_multi(pkt, ev, num_pkt);

		pktout = queue_context->dst_pktout;
		out    = queue_context->dst_pktio;

		send_packets(test_global, pkt, num_pkt, out, pktout, worker_id);

		if (odp_unlikely(test_global->opt.collect_stat))
			test_global->worker_stat[worker_id].rx_pkt += num_pkt;
	}

	printf("Worker %i stopped\n", worker_id);

	return 0;
}

static inline void enqueue_events(odp_queue_t dst_queue, odp_event_t ev[],
				  int num, int worker_id)
{
	int sent, drop;

	sent = odp_queue_enq_multi(dst_queue, ev, num);

	if (odp_unlikely(sent < 0))
		sent = 0;

	drop = num - sent;

	if (odp_unlikely(drop))
		odp_event_free_multi(&ev[sent], drop);

	if (odp_unlikely(test_global->opt.collect_stat))
		test_global->worker_stat[worker_id].pipe_drop += drop;
}

static inline odp_queue_t next_queue(test_global_t *test_global, int input,
				     uint16_t stage, uint16_t queue_idx)
{
	return test_global->pipe_queue[input][stage].queue[queue_idx];
}

static int worker_thread_pipeline(void *arg)
{
	int i, num_pkt, input, output, output_queue;
	odp_queue_t queue, dst_queue;
	odp_pktout_queue_t pktout;
	pipe_queue_context_t *pipe_context;
	uint16_t stage, queue_idx;
	worker_arg_t *worker_arg = arg;
	test_global_t *test_global = worker_arg->test_global_ptr;
	int worker_id = worker_arg->worker_id;
	int pipe_stages = test_global->opt.pipe_stages;
	int pipe_queues = test_global->opt.pipe_queues;
	int num_pktio = test_global->opt.num_pktio;
	int num_pktio_queue = test_global->opt.num_pktio_queue;
	uint32_t polls = 0;
	int burst_size = test_global->opt.burst_size;

	printf("Worker %i started\n", worker_id);

	/* Wait for other workers to start */
	odp_barrier_wait(&test_global->worker_start);

	while (1) {
		odp_event_t ev[burst_size];
		odp_packet_t pkt[burst_size];

		num_pkt = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					     ev, burst_size);

		polls++;

		if (polls == CHECK_PERIOD) {
			polls = 0;
			if (test_global->stop_workers)
				break;
		}

		if (num_pkt <= 0)
			continue;

		pipe_context = odp_queue_context(queue);
		stage = pipe_context->stage;
		queue_idx = pipe_context->queue_idx;

		/* A queue is connected to a single input interface. All
		 * packets from a queue are from the same interface. */
		input = odp_packet_input_index(odp_packet_from_event(ev[0]));

		if (DEBUG_PRINT)
			printf("worker %i: stage %u, idx %u, %i packets\n",
			       worker_id, stage, queue_idx, num_pkt);

		if (stage == 0) {
			if (odp_unlikely(test_global->opt.collect_stat))
				test_global->worker_stat[worker_id].rx_pkt +=
					num_pkt;

			/* The first stage (packet input). Forward packet flows
			 * into first pipeline queues. */
			if (pipe_queues > num_pktio_queue) {
				/* More pipeline queues than input queues.
				 * Use flow hash to spread flows into pipeline
				 * queues. */
				odp_packet_t p;
				worker_stat_t *stat;
				uint32_t hash;
				uint16_t idx;
				int drop = 0;

				stat = &test_global->worker_stat[worker_id];

				for (i = 0; i < num_pkt; i++) {
					p = odp_packet_from_event(ev[i]);
					hash = odp_packet_flow_hash(p);
					idx = queue_idx;

					if (odp_packet_has_flow_hash(p))
						idx = hash % pipe_queues;

					dst_queue = next_queue(test_global,
							       input, stage,
							       idx);

					if (odp_queue_enq(dst_queue, ev[i])) {
						odp_event_free(ev[i]);
						drop++;
					}
				}

				if (odp_unlikely(test_global->opt.collect_stat))
					stat->pipe_drop += drop;
			} else {
				queue_idx = queue_idx % pipe_queues;
				dst_queue = next_queue(test_global, input,
						       stage, queue_idx);

				enqueue_events(dst_queue, ev, num_pkt,
					       worker_id);
			}
			continue;
		}

		if (stage < pipe_stages) {
			/* Middle stages */
			dst_queue = next_queue(test_global, input, stage,
					       queue_idx);
			enqueue_events(dst_queue, ev, num_pkt, worker_id);

			if (odp_unlikely(test_global->opt.collect_stat))
				test_global->worker_stat[worker_id].pipe_pkt +=
					num_pkt;

			continue;
		}

		/* The last stage, send packets out */
		odp_packet_from_event_multi(pkt, ev, num_pkt);

		/* If single interface loopback, otherwise forward to the next
		 * interface. */
		output = (input + 1) % num_pktio;
		output_queue = queue_idx % num_pktio_queue;
		pktout = test_global->pktio[output].pktout[output_queue];

		send_packets(test_global, pkt, num_pkt, output, pktout,
			     worker_id);
	}

	printf("Worker %i stopped\n", worker_id);

	return 0;
}

static int worker_thread_timers(void *arg)
{
	int num, num_pkt, out, tmos, i, src_pktio, src_queue;
	odp_pktout_queue_t pktout;
	odp_queue_t queue;
	pktin_queue_context_t *queue_context;
	odp_timer_t timer;
	odp_timer_set_t ret;
	worker_arg_t *worker_arg = arg;
	test_global_t *test_global = worker_arg->test_global_ptr;
	int worker_id = worker_arg->worker_id;
	uint32_t polls = 0;
	int burst_size = test_global->opt.burst_size;
	uint64_t tick = test_global->timer.timeout_tick;

	printf("Worker (timers) %i started\n", worker_id);

	/* Wait for other workers to start */
	odp_barrier_wait(&test_global->worker_start);

	while (1) {
		odp_event_t ev[burst_size];
		odp_packet_t pkt[burst_size];

		num = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					 ev, burst_size);

		polls++;

		if (polls == CHECK_PERIOD) {
			polls = 0;
			if (test_global->stop_workers)
				break;
		}

		if (num <= 0)
			continue;

		tmos = 0;
		queue_context = odp_queue_context(queue);
		src_pktio = queue_context->src_pktio;
		src_queue = queue_context->src_queue;
		timer = test_global->timer.timer[src_pktio][src_queue];

		for (i = 0; i < num; i++) {
			if (odp_unlikely(odp_event_type(ev[i]) ==
					 ODP_EVENT_TIMEOUT)) {
				tmos++;
				ret = odp_timer_set_rel(timer, tick, &ev[i]);

				if (odp_unlikely(ret != ODP_TIMER_SUCCESS)) {
					/* Should never happen. Timeout event
					 * has been received, timer should be
					 * ready to be set again. */
					printf("Expired timer reset failed "
					       "%i\n", ret);
					odp_event_free(ev[i]);
				}

				if (odp_unlikely(tmos > 1)) {
					/* Should never happen */
					printf("Too many timeouts\n");
				}
			} else {
				pkt[i - tmos] = odp_packet_from_event(ev[i]);
			}
		}

		if (tmos == 0) {
			/* Reset timer with existing timeout event */
			ret = odp_timer_set_rel(timer, tick, NULL);

			if (odp_unlikely(ret != ODP_TIMER_SUCCESS &&
					 ret != ODP_TIMER_NOEVENT)) {
				/* Tick period is too short or long. Normally,
				 * reset either succeeds or fails due to timer
				 * expiration, in which case timeout event will
				 * be received soon and reset will be done
				 * then. */
				printf("Timer reset failed %i\n", ret);
			}
		}

		num_pkt = num - tmos;

		if (DEBUG_PRINT)
			printf("worker %i: [%i/%i] -> [%i/%i], %i packets "
			       "%i timeouts\n",
			       worker_id,
			       queue_context->src_pktio,
			       queue_context->src_queue,
			       queue_context->dst_pktio,
			       queue_context->dst_queue, num_pkt, tmos);

		if (odp_unlikely(test_global->opt.collect_stat && tmos))
			test_global->worker_stat[worker_id].tmo += tmos;

		if (odp_unlikely(num_pkt == 0))
			continue;

		pktout = queue_context->dst_pktout;
		out    = queue_context->dst_pktio;

		send_packets(test_global, pkt, num_pkt, out, pktout, worker_id);

		if (odp_unlikely(test_global->opt.collect_stat))
			test_global->worker_stat[worker_id].rx_pkt += num_pkt;
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
	       "  -i, --interface <name>    Packet IO interfaces (comma-separated, no spaces)\n"
	       "  -c, --num_cpu <number>    Worker thread count. Default: 1\n"
	       "  -q, --num_queue <number>  Number of pktio queues. Default: Worker thread count\n"
	       "  -b, --burst <number>      Maximum number of events requested from scheduler. Default: 32\n"
	       "  -t, --timeout <number>    Flow inactivity timeout (in usec) per packet. Default: 0 (don't use timers)\n"
	       "  --pipe-stages <number>    Number of pipeline stages per interface\n"
	       "  --pipe-queues <number>    Number of queues per pipeline stage\n"
	       "  --pipe-queue-size <num>   Number of events a pipeline queue must be able to store. Default 256.\n"
	       "  -m, --sched_mode <mode>   Scheduler synchronization mode for all queues. 1: parallel, 2: atomic, 3: ordered. Default: 2\n"
	       "  -s, --stat                Collect statistics.\n"
	       "  -h, --help                Display help and exit.\n\n",
	       NO_PATH(progname));
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int i, opt, long_index;
	char *name, *str;
	int len, str_len, sched_mode;
	const struct option longopts[] = {
		{"interface",   required_argument, NULL, 'i'},
		{"num_cpu",     required_argument, NULL, 'c'},
		{"num_queue",   required_argument, NULL, 'q'},
		{"burst",       required_argument, NULL, 'b'},
		{"timeout",     required_argument, NULL, 't'},
		{"sched_mode",  required_argument, NULL, 'm'},
		{"pipe-stages", required_argument, NULL,  0},
		{"pipe-queues", required_argument, NULL,  1},
		{"pipe-queue-size", required_argument, NULL,  2},
		{"stat",        no_argument,       NULL, 's'},
		{"help",        no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+i:c:q:b:t:m:sh";
	int ret = 0;

	memset(test_options, 0, sizeof(test_options_t));

	test_options->sched_mode = SCHED_MODE_ATOMIC;
	test_options->num_worker = 1;
	test_options->num_pktio_queue = 0;
	test_options->burst_size = 32;
	test_options->pipe_queue_size = 256;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 0:
			test_options->pipe_stages = atoi(optarg);
			break;
		case 1:
			test_options->pipe_queues = atoi(optarg);
			break;
		case 2:
			test_options->pipe_queue_size = atoi(optarg);
			break;
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

				name = test_options->pktio_name[i];
				memcpy(name, str, len);
				str += len + 1;
				i++;
			}

			test_options->num_pktio = i;

			break;
		case 'c':
			test_options->num_worker = atoi(optarg);
			break;
		case 'q':
			test_options->num_pktio_queue = atoi(optarg);
			break;
		case 'b':
			test_options->burst_size = atoi(optarg);
			break;
		case 't':
			test_options->timeout_us = atol(optarg);
			break;
		case 'm':
			test_options->sched_mode = atoi(optarg);
			break;
		case 's':
			test_options->collect_stat = 1;
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

	if (test_options->timeout_us && test_options->pipe_stages) {
		printf("Error: Cannot run timeout and pipeline tests simultaneously\n");
		ret = -1;
	}

	if (test_options->pipe_stages > MAX_PIPE_STAGES) {
		printf("Error: Too many pipeline stages\n");
		ret = -1;
	}

	if (test_options->pipe_queues > MAX_PIPE_QUEUES) {
		printf("Error: Too many queues per pipeline stage\n");
		ret = -1;
	}

	if (test_options->num_pktio == 0) {
		printf("Error: At least one pktio interface needed.\n");
		ret = -1;
	}

	sched_mode = test_options->sched_mode;
	if (sched_mode != SCHED_MODE_PARAL &&
	    sched_mode != SCHED_MODE_ATOMIC &&
	    sched_mode != SCHED_MODE_ORDER) {
		printf("Error: Bad scheduler mode: %i\n", sched_mode);
		ret = -1;
	}

	if (test_options->num_pktio_queue == 0)
		test_options->num_pktio_queue = test_options->num_worker;

	return ret;
}

static odp_schedule_sync_t sched_sync_mode(test_global_t *test_global)
{
	switch (test_global->opt.sched_mode) {
	case SCHED_MODE_PARAL:
		return ODP_SCHED_SYNC_PARALLEL;
	case SCHED_MODE_ATOMIC:
		return ODP_SCHED_SYNC_ATOMIC;
	case SCHED_MODE_ORDER:
		return ODP_SCHED_SYNC_ORDERED;
	default:
		return -1;
	}
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

	odp_schedule_config_init(&test_global->schedule_config);
	odp_schedule_config(&test_global->schedule_config);

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capability failed.\n");
		return -1;
	}

	pkt_len = MAX_PKT_LEN;
	pkt_num = MAX_PKT_NUM;

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len)
		pkt_len = pool_capa.pkt.max_len;

	if (pool_capa.pkt.max_num && pkt_num > pool_capa.pkt.max_num) {
		pkt_num = pool_capa.pkt.max_num;
		printf("Warning: Pool size rounded down to %u\n", pkt_num);
	}

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
		printf(" %s", test_global->opt.pktio_name[i]);

	printf("\n"
	       "  queues per interface:  %i\n",
	       test_global->opt.num_pktio_queue);

	printf("  burst size:            %u\n", test_global->opt.burst_size);
	printf("  collect statistics:    %u\n", test_global->opt.collect_stat);
	printf("  timeout usec:          %li\n", test_global->opt.timeout_us);

	printf("\n");
}

static void print_stat(test_global_t *test_global, uint64_t nsec)
{
	int i;
	uint64_t rx, tx, pipe, drop, tmo;
	uint64_t rx_sum = 0;
	uint64_t tx_sum = 0;
	uint64_t pipe_sum = 0;
	uint64_t tmo_sum = 0;
	double sec = 0.0;

	printf("\nTest statistics\n");
	printf("  worker           rx_pkt           tx_pkt             pipe          dropped              tmo\n");

	for (i = 0; i < test_global->opt.num_worker; i++) {
		rx = test_global->worker_stat[i].rx_pkt;
		tx = test_global->worker_stat[i].tx_pkt;
		pipe = test_global->worker_stat[i].pipe_pkt;
		tmo = test_global->worker_stat[i].tmo;
		rx_sum += rx;
		tx_sum += tx;
		pipe_sum += pipe;
		tmo_sum += tmo;
		drop = test_global->worker_stat[i].tx_drop +
		       test_global->worker_stat[i].pipe_drop;

		printf("  %6i %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16"
		       PRIu64 " %16" PRIu64 "\n", i, rx, tx, pipe, drop, tmo);
	}

	test_global->rx_pkt_sum = rx_sum;
	test_global->tx_pkt_sum = tx_sum;
	drop = rx_sum - tx_sum;

	printf("         ------------------------------------------------------------------------------------\n");
	printf("  total  %16" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16"
	       PRIu64 " %16" PRIu64 "\n\n", rx_sum, tx_sum, pipe_sum, drop,
	       tmo_sum);

	sec = nsec / 1000000000.0;
	printf("  Total test time: %.2f sec\n", sec);
	printf("  Rx packet rate:  %.2f pps\n", rx_sum / sec);
	printf("  Tx packet rate:  %.2f pps\n", tx_sum / sec);
	printf("  Drop rate:       %.2f pps\n", drop / sec);
	printf("  Timeout rate:    %.2f per sec\n\n", tmo_sum / sec);
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
	unsigned int j;

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

	sched_sync = sched_sync_mode(test_global);

	for (i = 0; i < num_pktio; i++)
		test_global->pktio[i].pktio = ODP_PKTIO_INVALID;

	/* Open and configure interfaces */
	for (i = 0; i < num_pktio; i++) {
		name  = test_global->opt.pktio_name[i];
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

		for (j = 0; j < num_queue; j++) {
			odp_queue_t queue;
			void *ctx;
			uint32_t len = sizeof(pktin_queue_context_t);

			queue = test_global->pktio[i].input_queue[j];
			ctx = &test_global->pktio[i].queue_context[j];

			if (odp_queue_context_set(queue, ctx, len)) {
				printf("Error (%s): Queue ctx set failed.\n",
				       name);
				return -1;
			}
		}

		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.num_queues  = num_queue;
		pktout_param.op_mode     = ODP_PKTIO_OP_MT_UNSAFE;

		if (test_global->opt.pipe_stages)
			pktout_param.op_mode = ODP_PKTIO_OP_MT;

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
	int num_queue;
	odp_pktout_queue_t pktout;
	pktin_queue_context_t *ctx;

	num_pktio = test_global->opt.num_pktio;
	num_queue = test_global->opt.num_pktio_queue;

	printf("Forwarding table (pktio indexes)\n");

	/* If single interface loopback, otherwise forward to the next
	 * interface. */
	for (input = 0; input < num_pktio; input++) {
		output = (input + 1) % num_pktio;
		printf("  input %i, output %i\n", input, output);

		for (i = 0; i < num_queue; i++) {
			ctx = &test_global->pktio[input].queue_context[i];
			pktout = test_global->pktio[output].pktout[i];
			ctx->stage      = 0;
			ctx->queue_idx  = i;
			ctx->dst_pktout = pktout;
			ctx->dst_pktio  = output;
			ctx->dst_queue  = i;
			ctx->src_pktio  = input;
			ctx->src_queue  = i;
		}
	}

	printf("\n");
}

static int start_pktios(test_global_t *test_global)
{
	int i;

	for (i = 0; i < test_global->opt.num_pktio; i++) {
		if (odp_pktio_start(test_global->pktio[i].pktio)) {
			printf("Error (%s): Pktio start failed.\n",
			       test_global->opt.pktio_name[i]);

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
			       test_global->opt.pktio_name[i]);
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
			       test_global->opt.pktio_name[i]);
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

static int create_pipeline_queues(test_global_t *test_global)
{
	int i, j, k, num_pktio, stages, queues, ctx_size;
	pipe_queue_context_t *ctx;
	odp_queue_param_t queue_param;
	odp_schedule_sync_t sched_sync;
	int ret = 0;

	num_pktio = test_global->opt.num_pktio;
	stages = test_global->opt.pipe_stages;
	queues = test_global->opt.pipe_queues;
	sched_sync = sched_sync_mode(test_global);

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	queue_param.sched.sync  = sched_sync;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	queue_param.size = test_global->opt.pipe_queue_size;
	if (test_global->schedule_config.queue_size &&
	    queue_param.size > test_global->schedule_config.queue_size) {
		printf("Error: Pipeline queue max size is %u\n",
		       test_global->schedule_config.queue_size);
		return -1;
	}

	ctx_size = sizeof(pipe_queue_context_t);

	for (i = 0; i < stages; i++) {
		for (j = 0; j < queues; j++) {
			ctx = &test_global->pipe_queue_ctx[i][j].ctx;

			/* packet input is stage 0 */
			ctx->stage = i + 1;
			ctx->queue_idx = j;
		}
	}

	for (k = 0; k < num_pktio; k++) {
		for (i = 0; i < stages; i++) {
			for (j = 0; j < queues; j++) {
				odp_queue_t q;

				q = odp_queue_create(NULL, &queue_param);
				test_global->pipe_queue[k][i].queue[j] = q;

				if (q == ODP_QUEUE_INVALID) {
					printf("Error: Queue create failed [%i] %i/%i\n",
					       k, i, j);
					ret = -1;
					break;
				}

				ctx = &test_global->pipe_queue_ctx[i][j].ctx;

				if (odp_queue_context_set(q, ctx, ctx_size)) {
					printf("Error: Queue ctx set failed [%i] %i/%i\n",
					       k, i, j);
					ret = -1;
					break;
				}
			}
		}
	}

	return ret;
}

static void destroy_pipeline_queues(test_global_t *test_global)
{
	int i, j, k, num_pktio, stages, queues;
	odp_queue_t queue;

	num_pktio = test_global->opt.num_pktio;
	stages = test_global->opt.pipe_stages;
	queues = test_global->opt.pipe_queues;

	for (k = 0; k < num_pktio; k++) {
		for (i = 0; i < stages; i++) {
			for (j = 0; j < queues; j++) {
				queue = test_global->pipe_queue[k][i].queue[j];

				if (queue == ODP_QUEUE_INVALID) {
					printf("Error: Bad queue handle [%i] %i/%i\n",
					       k, i, j);
					return;
				}

				if (odp_queue_destroy(queue)) {
					printf("Error: Queue destroy failed [%i] %i/%i\n",
					       k, i, j);
					return;
				}
			}
		}
	}
}

static int create_timers(test_global_t *test_global)
{
	int num_timer, num_pktio, num_queue, i, j;
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_timer_pool_t timer_pool;
	odp_timer_pool_param_t timer_param;
	odp_timer_capability_t timer_capa;
	odp_timer_t timer;
	odp_queue_t queue;
	uint64_t res_ns, tick;
	uint64_t timeout_ns = 1000 * test_global->opt.timeout_us;

	num_pktio = test_global->opt.num_pktio;
	num_queue = test_global->opt.num_pktio_queue;
	num_timer = num_pktio * num_queue;

	/* Always init globals for destroy calls */
	test_global->timer.timer_pool = ODP_TIMER_POOL_INVALID;
	test_global->timer.timeout_pool = ODP_POOL_INVALID;

	for (i = 0; i < num_pktio; i++)
		for (j = 0; j < num_queue; j++)
			test_global->timer.timer[i][j] = ODP_TIMER_INVALID;

	/* Timers not used */
	if (test_global->opt.timeout_us == 0)
		return 0;

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa)) {
		printf("Timer capa failed\n");
		return -1;
	}

	res_ns = timeout_ns / 10;

	if (timer_capa.highest_res_ns > res_ns) {
		printf("Timeout too short. Min timeout %" PRIu64 " usec\n",
		       timer_capa.highest_res_ns / 100);
		return -1;
	}

	memset(&timer_param, 0, sizeof(odp_timer_pool_param_t));

	timer_param.res_ns     = res_ns;
	timer_param.min_tmo    = timeout_ns;
	timer_param.max_tmo    = timeout_ns;
	timer_param.num_timers = num_timer;
	timer_param.clk_src    = ODP_CLOCK_CPU;

	timer_pool = odp_timer_pool_create("sched_pktio_timer", &timer_param);

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		printf("Timer pool create failed\n");
		return -1;
	}

	test_global->timer.timer_pool = timer_pool;
	tick = odp_timer_ns_to_tick(timer_pool, timeout_ns);
	test_global->timer.timeout_tick = tick;

	odp_timer_pool_start();

	for (i = 0; i < num_pktio; i++) {
		for (j = 0; j < num_queue; j++) {
			queue = test_global->pktio[i].input_queue[j];
			timer = odp_timer_alloc(timer_pool, queue, NULL);

			if (timer == ODP_TIMER_INVALID) {
				printf("Timer alloc failed.\n");
				return -1;
			}

			test_global->timer.timer[i][j] = timer;
		}
	}

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = num_timer;

	pool = odp_pool_create("timeout pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Timeout pool create failed.\n");
		return -1;
	}

	test_global->timer.timeout_pool = pool;

	return 0;
}

static int start_timers(test_global_t *test_global)
{
	int i, j;
	odp_event_t event;
	odp_timeout_t timeout;
	odp_timer_t timer;
	odp_timer_set_t ret;
	uint64_t timeout_tick = test_global->timer.timeout_tick;
	int num_pktio = test_global->opt.num_pktio;
	int num_queue = test_global->opt.num_pktio_queue;
	odp_pool_t pool = test_global->timer.timeout_pool;

	/* Timers not used */
	if (test_global->opt.timeout_us == 0)
		return 0;

	/* Delay the first timeout so that workers have time to startup */
	timeout_tick += odp_timer_ns_to_tick(test_global->timer.timer_pool,
					     TIMEOUT_OFFSET_NS);

	for (i = 0; i < num_pktio; i++) {
		for (j = 0; j < num_queue; j++) {
			timer = test_global->timer.timer[i][j];

			timeout = odp_timeout_alloc(pool);
			if (timeout == ODP_TIMEOUT_INVALID) {
				printf("Timeout alloc failed\n");
				return -1;
			}

			event = odp_timeout_to_event(timeout);

			ret = odp_timer_set_rel(timer, timeout_tick, &event);

			if (ret != ODP_TIMER_SUCCESS) {
				printf("Timer set failed\n");
				return -1;
			}
		}
	}

	return 0;
}

static void destroy_timers(test_global_t *test_global)
{
	int i, j;
	odp_event_t event;
	odp_timer_t timer;
	int num_pktio = test_global->opt.num_pktio;
	int num_queue = test_global->opt.num_pktio_queue;
	odp_timer_pool_t timer_pool = test_global->timer.timer_pool;
	odp_pool_t pool = test_global->timer.timeout_pool;

	if (timer_pool == ODP_TIMER_POOL_INVALID)
		return;

	for (i = 0; i < num_pktio; i++) {
		for (j = 0; j < num_queue; j++) {
			timer = test_global->timer.timer[i][j];

			if (timer == ODP_TIMER_INVALID)
				break;

			event = odp_timer_free(timer);

			if (event != ODP_EVENT_INVALID)
				odp_event_free(event);
		}
	}

	if (pool != ODP_POOL_INVALID) {
		if (odp_pool_destroy(pool))
			printf("Timeout pool destroy failed\n");
	}

	odp_timer_pool_destroy(timer_pool);
}

static void start_workers(odph_odpthread_t thread[],
			  test_global_t *test_global)
{
	int i;
	odp_cpumask_t cpumask;
	odph_odpthread_params_t param;
	int num = test_global->opt.num_worker;

	memset(&param, 0, sizeof(odph_odpthread_params_t));

	if (test_global->opt.timeout_us)
		param.start = worker_thread_timers;
	else if (test_global->opt.pipe_stages)
		param.start = worker_thread_pipeline;
	else
		param.start = worker_thread_direct;

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
	odph_helper_options_t helper_options;
	odph_odpthread_t thread[MAX_WORKERS];
	test_options_t test_options;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		printf("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, sig_handler);

	if (parse_options(argc, argv, &test_options))
		return -1;

	/* List features not to be used (may optimize performance) */
	odp_init_param_init(&init);
	init.not_used.feat.cls    = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec  = 1;
	init.not_used.feat.tm     = 1;
	init.not_used.feat.timer  = 1;

	if (test_options.timeout_us)
		init.not_used.feat.timer = 0;

	init.mem_model = helper_options.mem_model;

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

	memcpy(&test_global->opt, &test_options, sizeof(test_options_t));

	odp_sys_info_print();

	if (config_setup(test_global))
		goto quit;

	print_config(test_global);

	if (open_pktios(test_global))
		goto quit;

	link_pktios(test_global);

	if (create_pipeline_queues(test_global))
		goto quit;

	if (create_timers(test_global))
		goto quit;

	if (start_timers(test_global))
		goto quit;

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
	destroy_pipeline_queues(test_global);
	destroy_timers(test_global);

	if (test_global->opt.collect_stat) {
		print_stat(test_global, odp_time_diff_ns(t2, t1));

		/* Encode return value for validation test usage. */
		if (test_global->rx_pkt_sum > TEST_PASSED_LIMIT)
			ret += 1;

		if (test_global->tx_pkt_sum > TEST_PASSED_LIMIT)
			ret += 2;
	}
	test_global = NULL;
	odp_mb_full();

	if (odp_shm_free(shm)) {
		printf("Error: shm free failed.\n");
		ret = -1;
	}

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		ret = -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		ret = -1;
	}

	return ret;
}
