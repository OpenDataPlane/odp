/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>

typedef struct test_options_t {
	uint32_t num_queue;
	uint32_t num_event;
	uint32_t num_round;
	odp_nonblocking_t nonblock;

} test_options_t;

static void print_usage(void)
{
	printf("\n"
	       "Plain queue performance test\n"
	       "\n"
	       "Usage: odp_queue_perf [options]\n"
	       "\n"
	       "  -q, --num_queue        Number of queues\n"
	       "  -e, --num_event        Number of events per queue\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -l, --lockfree         Lockfree queues\n"
	       "  -w, --waitfree         Waitfree queues\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_queue", required_argument, NULL, 'q'},
		{"num_event", required_argument, NULL, 'e'},
		{"num_round", required_argument, NULL, 'r'},
		{"lockfree",  no_argument,       NULL, 'l'},
		{"waitfree",  no_argument,       NULL, 'w'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+q:e:r:lwh";

	test_options->num_queue = 1;
	test_options->num_event = 1;
	test_options->num_round = 1000;
	test_options->nonblock  = ODP_BLOCKING;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'q':
			test_options->num_queue = atoi(optarg);
			break;
		case 'e':
			test_options->num_event = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'l':
			test_options->nonblock = ODP_NONBLOCKING_LF;
			break;
		case 'w':
			test_options->nonblock = ODP_NONBLOCKING_WF;
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	return ret;
}

static int test_queue(test_options_t *test_options)
{
	odp_pool_capability_t pool_capa;
	odp_queue_capability_t queue_capa;
	odp_pool_param_t pool_param;
	odp_queue_param_t queue_param;
	odp_pool_t pool;
	odp_event_t ev;
	uint32_t i, j, rounds;
	uint64_t c1, c2, diff, ops, nsec;
	odp_time_t t1, t2;
	uint64_t num_retry = 0;
	odp_nonblocking_t nonblock = test_options->nonblock;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_event = test_options->num_event;
	uint32_t num_round = test_options->num_round;
	uint32_t tot_event = num_queue * num_event;
	odp_queue_t queue[num_queue];
	odp_event_t event[tot_event];

	printf("\nTesting %s queues\n",
	       nonblock == ODP_BLOCKING ? "NORMAL" :
	       (nonblock == ODP_NONBLOCKING_LF ? "LOCKFREE" :
	       (nonblock == ODP_NONBLOCKING_WF ? "WAITFREE" : "???")));
	printf("  num rounds           %u\n", num_round);
	printf("  num queues           %u\n", num_queue);
	printf("  num events per queue %u\n\n", num_event);

	for (i = 0; i < num_queue; i++)
		queue[i] = ODP_QUEUE_INVALID;

	for (i = 0; i < tot_event; i++)
		event[i] = ODP_EVENT_INVALID;

	if (odp_queue_capability(&queue_capa)) {
		printf("Error: Queue capa failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	if (nonblock == ODP_BLOCKING) {
		if (num_queue > queue_capa.plain.max_num) {
			printf("Max queues supported %u\n",
			       queue_capa.plain.max_num);
			return -1;
		}

		if (num_event > queue_capa.plain.max_size) {
			printf("Max queue size supported %u\n",
			       queue_capa.plain.max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_LF) {
		if (queue_capa.plain.lockfree.max_num == 0) {
			printf("Lockfree queues not supported\n");
			return 0;
		}

		if (num_queue > queue_capa.plain.lockfree.max_num) {
			printf("Max lockfree queues supported %u\n",
			       queue_capa.plain.lockfree.max_num);
			return -1;
		}

		if (num_event > queue_capa.plain.lockfree.max_size) {
			printf("Max lockfree queue size supported %u\n",
			       queue_capa.plain.lockfree.max_size);
			return -1;
		}
	} else if (nonblock == ODP_NONBLOCKING_WF) {
		if (queue_capa.plain.waitfree.max_num == 0) {
			printf("Waitfree queues not supported\n");
			return 0;
		}

		if (num_queue > queue_capa.plain.waitfree.max_num) {
			printf("Max waitfree queues supported %u\n",
			       queue_capa.plain.waitfree.max_num);
			return -1;
		}

		if (num_event > queue_capa.plain.waitfree.max_size) {
			printf("Max waitfree queue size supported %u\n",
			       queue_capa.plain.waitfree.max_size);
			return -1;
		}
	} else {
		printf("Error: Bad queue blocking type\n");
		return -1;
	}

	if (tot_event > pool_capa.buf.max_num) {
		printf("Max events supported %u\n", pool_capa.buf.max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = tot_event;

	pool = odp_pool_create("queue perf pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_PLAIN;
	queue_param.nonblocking = nonblock;
	queue_param.size        = num_event;

	for (i = 0; i < num_queue; i++) {
		queue[i] = odp_queue_create(NULL, &queue_param);

		if (queue[i] == ODP_QUEUE_INVALID) {
			printf("Error: Queue create failed %u.\n", i);
			goto error;
		}
	}

	for (i = 0; i < tot_event; i++) {
		event[i] = odp_buffer_to_event(odp_buffer_alloc(pool));

		if (event[i] == ODP_EVENT_INVALID) {
			printf("Error: Event alloc failed %u.\n", i);
			goto error;
		}
	}

	for (i = 0; i < num_queue; i++) {
		for (j = 0; j < num_event; j++) {
			uint32_t id = i * num_event + j;

			if (odp_queue_enq(queue[i], event[id])) {
				printf("Error: Queue enq failed %u/%u\n", i, j);
				goto error;
			}

			event[id] = ODP_EVENT_INVALID;
		}
	}

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		int retry = 0;

		for (i = 0; i < num_queue; i++) {
			ev = odp_queue_deq(queue[i]);

			if (ev == ODP_EVENT_INVALID) {
				if (retry < 5) {
					retry++;
					num_retry++;
					continue;
				}

				printf("Error: Queue deq failed %u\n", i);
				goto error;
			}

			retry = 0;

			if (odp_queue_enq(queue[i], ev)) {
				printf("Error: Queue enq failed %u\n", i);
				goto error;
			}
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec = odp_time_diff_ns(t2, t1);
	diff = odp_cpu_cycles_diff(c2, c1);
	ops = num_round * num_queue;

	printf("RESULT:\n");
	printf("  num deq + enq operations: %" PRIu64 "\n", ops);
	printf("  duration (nsec):          %" PRIu64 "\n", nsec);
	printf("  num cycles:               %" PRIu64 "\n", diff);
	printf("  cycles per deq + enq:     %.3f\n", (double)diff / ops);
	printf("  num retries:              %" PRIu64 "\n\n", num_retry);

error:

	for (i = 0; i < num_queue; i++) {
		for (j = 0; j < num_event; j++) {
			ev = odp_queue_deq(queue[i]);

			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}
	}

	for (i = 0; i < tot_event; i++) {
		if (event[i] != ODP_EVENT_INVALID)
			odp_event_free(event[i]);
	}

	for (i = 0; i < num_queue; i++) {
		if (queue[i] == ODP_QUEUE_INVALID)
			break;

		if (odp_queue_destroy(queue[i])) {
			printf("Error: Queue destroy failed %u.\n", i);
			break;
		}
	}

	if (odp_pool_destroy(pool)) {
		printf("Error: Pool destroy failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	test_options_t test_options;

	if (parse_options(argc, argv, &test_options))
		return -1;

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	if (test_queue(&test_options))
		printf("Error: Queue test failed.\n");

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		return -1;
	}

	return 0;
}
