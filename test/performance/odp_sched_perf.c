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
#include <odp/helper/odph_api.h>

#define MAX_QUEUES  (256 * 1024)
#define MAX_GROUPS  256

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_queue;
	uint32_t num_dummy;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t num_group;
	uint32_t num_join;
	uint32_t max_burst;
	int      queue_type;
	int      forward;
	uint32_t queue_size;
	uint32_t tot_queue;
	uint32_t tot_event;
	uint64_t wait_ns;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t enqueues;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;
	uint64_t waits;

} test_stat_t;

typedef struct thread_arg_t {
	void *global;
	int first_group;

} thread_arg_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_schedule_config_t schedule_config;
	odp_barrier_t barrier;
	odp_pool_t pool;
	odp_cpumask_t cpumask;
	odp_queue_t queue[MAX_QUEUES];
	odp_schedule_group_t group[MAX_GROUPS];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];

} test_global_t;

test_global_t test_global;

static void print_usage(void)
{
	printf("\n"
	       "Scheduler performance test\n"
	       "\n"
	       "Usage: odp_sched_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1.\n"
	       "  -q, --num_queue        Number of queues. Default: 1.\n"
	       "  -d, --num_dummy        Number of empty queues. Default: 0.\n"
	       "  -e, --num_event        Number of events per queue. Default: 100.\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -g, --num_group        Number of schedule groups. Round robins threads and queues into groups.\n"
	       "                         0: SCHED_GROUP_ALL (default)\n"
	       "  -j, --num_join         Number of groups a thread joins. Threads are divide evenly into groups,\n"
	       "                         if num_cpu is multiple of num_group and num_group is multiple of num_join.\n"
	       "                         0: join all groups (default)\n"
	       "  -b, --burst            Maximum number of events per operation. Default: 100.\n"
	       "  -t, --type             Queue type. 0: parallel, 1: atomic, 2: ordered. Default: 0.\n"
	       "  -f, --forward          0: Keep event in the original queue, 1: Forward event to the next queue. Default: 0.\n"
	       "  -w, --wait_ns          Number of nsec to wait before enqueueing events. Default: 0.\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;
	uint32_t num_group, num_join;

	static const struct option longopts[] = {
		{"num_cpu",   required_argument, NULL, 'c'},
		{"num_queue", required_argument, NULL, 'q'},
		{"num_dummy", required_argument, NULL, 'd'},
		{"num_event", required_argument, NULL, 'e'},
		{"num_round", required_argument, NULL, 'r'},
		{"num_group", required_argument, NULL, 'g'},
		{"num_join",  required_argument, NULL, 'j'},
		{"burst",     required_argument, NULL, 'b'},
		{"type",      required_argument, NULL, 't'},
		{"forward",   required_argument, NULL, 'f'},
		{"wait_ns",   required_argument, NULL, 'w'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:q:d:e:r:g:j:b:t:f:w:h";

	test_options->num_cpu    = 1;
	test_options->num_queue  = 1;
	test_options->num_dummy  = 0;
	test_options->num_event  = 100;
	test_options->num_round  = 100000;
	test_options->num_group  = 0;
	test_options->num_join   = 0;
	test_options->max_burst  = 100;
	test_options->queue_type = 0;
	test_options->forward    = 0;
	test_options->wait_ns    = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'q':
			test_options->num_queue = atoi(optarg);
			break;
		case 'd':
			test_options->num_dummy = atoi(optarg);
			break;
		case 'e':
			test_options->num_event = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'g':
			test_options->num_group = atoi(optarg);
			break;
		case 'j':
			test_options->num_join = atoi(optarg);
			break;
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 't':
			test_options->queue_type = atoi(optarg);
			break;
		case 'f':
			test_options->forward = atoi(optarg);
			break;
		case 'w':
			test_options->wait_ns = atoll(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if ((test_options->num_queue + test_options->num_dummy) > MAX_QUEUES) {
		printf("Error: Too many queues. Max supported %i.\n",
		       MAX_QUEUES);
		ret = -1;
	}

	num_group = test_options->num_group;
	num_join  = test_options->num_join;
	if (num_group > MAX_GROUPS) {
		printf("Error: Too many groups. Max supported %i.\n",
		       MAX_GROUPS);
		ret = -1;
	}

	if (num_join > num_group) {
		printf("Error: num_join (%u) larger than num_group (%u).\n",
		       num_join, num_group);
		ret = -1;
	}

	if (num_join && num_group > (test_options->num_cpu * num_join)) {
		printf("WARNING: Too many groups (%u). Some groups (%u) are not served.\n\n",
		       num_group,
		       num_group - (test_options->num_cpu * num_join));

		if (test_options->forward) {
			printf("Error: Cannot forward when some queues are not served.\n");
			ret = -1;
		}
	}

	test_options->tot_queue = test_options->num_queue +
				  test_options->num_dummy;
	test_options->tot_event = test_options->num_queue *
				  test_options->num_event;

	test_options->queue_size = test_options->num_event;

	/* When forwarding, all events may end up into a single queue. */
	if (test_options->forward)
		test_options->queue_size = test_options->tot_event;

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		printf("Error: Too many workers. Maximum is %i.\n",
		       ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		printf("Error: Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu);

	return 0;
}

static int create_pool(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	uint32_t max_num;
	test_options_t *test_options = &global->test_options;
	uint32_t num_cpu   = test_options->num_cpu;
	uint32_t num_queue = test_options->num_queue;
	uint32_t num_dummy = test_options->num_dummy;
	uint32_t num_event = test_options->num_event;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t tot_queue = test_options->tot_queue;
	uint32_t tot_event = test_options->tot_event;
	uint32_t queue_size = test_options->queue_size;
	uint32_t num_group = test_options->num_group;
	uint32_t num_join = test_options->num_join;
	int      forward   = test_options->forward;
	uint64_t wait_ns = test_options->wait_ns;

	printf("\nScheduler performance test\n");
	printf("  num cpu          %u\n", num_cpu);
	printf("  num queues       %u\n", num_queue);
	printf("  num empty queues %u\n", num_dummy);
	printf("  total queues     %u\n", tot_queue);
	printf("  num groups       %u\n", num_group);
	printf("  num join         %u\n", num_join);
	printf("  events per queue %u\n", num_event);
	printf("  queue size       %u\n", queue_size);
	printf("  max burst size   %u\n", max_burst);
	printf("  total events     %u\n", tot_event);
	printf("  num rounds       %u\n", num_round);
	printf("  forward events   %i\n", forward ? 1 : 0);
	printf("  wait nsec        %" PRIu64 "\n", wait_ns);

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	max_num = pool_capa.buf.max_num;

	if (max_num && tot_event > max_num) {
		printf("Error: max events supported %u\n", max_num);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = tot_event;

	pool = odp_pool_create("sched perf", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	return 0;
}

static int create_groups(test_global_t *global)
{
	odp_schedule_capability_t sched_capa;
	odp_thrmask_t thrmask;
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_group = test_options->num_group;

	if (num_group == 0)
		return 0;

	if (odp_schedule_capability(&sched_capa)) {
		printf("Error: schedule capability failed\n");
		return -1;
	}

	if (num_group > sched_capa.max_groups) {
		printf("Error: Too many sched groups (max_groups capa %u)\n",
		       sched_capa.max_groups);
		return -1;
	}

	odp_thrmask_zero(&thrmask);

	for (i = 0; i < num_group; i++) {
		odp_schedule_group_t group;

		group = odp_schedule_group_create("test_group", &thrmask);

		if (group == ODP_SCHED_GROUP_INVALID) {
			printf("Error: Group create failed %u\n", i);
			return -1;
		}

		global->group[i] = group;
	}

	return 0;
}

static int create_queues(test_global_t *global)
{
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_schedule_sync_t sync;
	const char *type_str;
	uint32_t i, j, first;
	test_options_t *test_options = &global->test_options;
	uint32_t num_event = test_options->num_event;
	uint32_t queue_size = test_options->queue_size;
	uint32_t tot_queue = test_options->tot_queue;
	uint32_t num_group = test_options->num_group;
	int type = test_options->queue_type;
	odp_pool_t pool = global->pool;

	if (type == 0) {
		type_str = "parallel";
		sync = ODP_SCHED_SYNC_PARALLEL;
	} else if (type == 1) {
		type_str = "atomic";
		sync = ODP_SCHED_SYNC_ATOMIC;
	} else {
		type_str = "ordered";
		sync = ODP_SCHED_SYNC_ORDERED;
	}

	printf("  queue type       %s\n\n", type_str);

	if (tot_queue > global->schedule_config.num_queues) {
		printf("Max queues supported %u\n",
		       global->schedule_config.num_queues);
		return -1;
	}

	if (global->schedule_config.queue_size &&
	    queue_size > global->schedule_config.queue_size) {
		printf("Max queue size %u\n",
		       global->schedule_config.queue_size);
		return -1;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	queue_param.sched.sync  = sync;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.size = queue_size;

	for (i = 0; i < tot_queue; i++) {
		if (num_group) {
			odp_schedule_group_t group;

			/* Divide all queues evenly into groups */
			group = global->group[i % num_group];
			queue_param.sched.group = group;
		}

		queue = odp_queue_create(NULL, &queue_param);

		global->queue[i] = queue;

		if (queue == ODP_QUEUE_INVALID) {
			printf("Error: Queue create failed %u\n", i);
			return -1;
		}
	}

	first = test_options->num_dummy;

	/* Store events into queues. Dummy queues are allocated from
	 * the beginning of the array, so that usage of those affect allocation
	 * of active queues. Dummy queues are left empty. */
	for (i = first; i < tot_queue; i++) {
		queue = global->queue[i];

		if (test_options->forward) {
			uint32_t next = i + 1;

			if (next == tot_queue)
				next = first;

			if (odp_queue_context_set(queue, &global->queue[next],
						  sizeof(odp_queue_t))) {
				printf("Error: Context set failed %u\n", i);
				return -1;
			}
		}

		for (j = 0; j < num_event; j++) {
			buf = odp_buffer_alloc(pool);

			if (buf == ODP_BUFFER_INVALID) {
				printf("Error: Alloc failed %u/%u\n", i, j);
				return -1;
			}

			if (odp_queue_enq(queue, odp_buffer_to_event(buf))) {
				printf("Error: Enqueue failed %u/%u\n", i, j);
				return -1;
			}
		}
	}

	return 0;
}

static int join_group(test_global_t *global, int grp_index, int thr)
{
	odp_thrmask_t thrmask;
	odp_schedule_group_t group;

	odp_thrmask_zero(&thrmask);
	odp_thrmask_set(&thrmask, thr);
	group = global->group[grp_index];

	if (odp_schedule_group_join(group, &thrmask)) {
		printf("Error: Group %i join failed (thr %i)\n",
		       grp_index, thr);
		return -1;
	}

	return 0;
}

static int join_all_groups(test_global_t *global, int thr)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_group = test_options->num_group;

	if (num_group == 0)
		return 0;

	for (i = 0; i < num_group; i++) {
		if (join_group(global, i, thr)) {
			printf("Error: Group %u join failed (thr %i)\n",
			       i, thr);
			return -1;
		}
	}

	return 0;
}

static int destroy_queues(test_global_t *global)
{
	uint32_t i;
	odp_event_t ev;
	uint64_t wait;
	test_options_t *test_options = &global->test_options;
	uint32_t tot_queue = test_options->tot_queue;
	int thr = odp_thread_id();

	if (join_all_groups(global, thr))
		return -1;

	wait = odp_schedule_wait_time(200 * ODP_TIME_MSEC_IN_NS);

	while ((ev = odp_schedule(NULL, wait)) != ODP_EVENT_INVALID)
		odp_event_free(ev);

	for (i = 0; i < tot_queue; i++) {
		if (global->queue[i] != ODP_QUEUE_INVALID) {
			if (odp_queue_destroy(global->queue[i])) {
				printf("Error: Queue destroy failed %u\n", i);
				return -1;
			}
		}
	}

	return 0;
}

static int destroy_groups(test_global_t *global)
{
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_group = test_options->num_group;

	if (num_group == 0)
		return 0;

	for (i = 0; i < num_group; i++) {
		odp_schedule_group_t group = global->group[i];

		if (odp_schedule_group_destroy(group)) {
			printf("Error: Group destroy failed %u\n", i);
			return -1;
		}
	}

	return 0;
}

static int test_sched(void *arg)
{
	int num, num_enq, ret, thr;
	uint32_t i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, enqueues, waits;
	odp_time_t t1, t2;
	odp_queue_t queue;
	odp_queue_t *next;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t num_group = test_options->num_group;
	int forward = test_options->forward;
	uint64_t wait_ns = test_options->wait_ns;
	odp_event_t ev[max_burst];

	thr = odp_thread_id();

	if (num_group) {
		uint32_t num_join = test_options->num_join;

		if (num_join) {
			int pos = 0;
			int n = 512;
			char str[n];
			int group_index = thread_arg->first_group;

			pos += snprintf(&str[pos], n - pos,
					"Thread %i joined groups:", thr);

			for (i = 0; i < num_join; i++) {
				if (join_group(global, group_index, thr))
					return -1;

				pos += snprintf(&str[pos], n - pos, " %i",
						group_index);

				group_index = (group_index + 1) % num_group;
			}

			printf("%s\n", str);

		} else {
			if (join_all_groups(global, thr))
				return -1;
		}
	}

	for (i = 0; i < max_burst; i++)
		ev[i] = ODP_EVENT_INVALID;

	enqueues = 0;
	events = 0;
	waits = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		num = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					 ev, max_burst);

		if (odp_likely(num > 0)) {
			events += num;
			i = 0;

			if (odp_unlikely(forward)) {
				next  = odp_queue_context(queue);
				queue = *next;
			}

			if (odp_unlikely(wait_ns)) {
				waits++;
				odp_time_wait_ns(wait_ns);
			}

			while (num) {
				num_enq = odp_queue_enq_multi(queue, &ev[i],
							      num);

				if (num_enq < 0) {
					printf("Error: Enqueue failed. Round %u\n",
					       rounds);
					ret = -1;
					break;
				}

				num -= num_enq;
				i   += num_enq;
				enqueues++;
			}

			if (odp_unlikely(ret))
				break;

			continue;
		}

		/* <0 not specified as an error but checking anyway */
		if (num < 0) {
			printf("Error: Sched failed. Round %u\n", rounds);
			ret = -1;
			break;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds   = rounds;
	global->stat[thr].enqueues = enqueues;
	global->stat[thr].events   = events;
	global->stat[thr].nsec     = nsec;
	global->stat[thr].cycles   = cycles;
	global->stat[thr].waits    = waits;

	/* Pause scheduling before thread exit */
	odp_schedule_pause();

	while (1) {
		ev[0] = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (ev[0] == ODP_EVENT_INVALID)
			break;

		if (odp_unlikely(forward)) {
			next  = odp_queue_context(queue);
			queue = *next;
		}

		odp_queue_enq(queue, ev[0]);
	}

	return ret;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	uint32_t num_group = test_options->num_group;
	uint32_t num_join  = test_options->num_join;
	int num_cpu   = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	memset(global->thread_tbl, 0, sizeof(global->thread_tbl));
	memset(thr_param, 0, sizeof(thr_param));
	memset(&thr_common, 0, sizeof(thr_common));

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		thr_param[i].start    = test_sched;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		global->thread_arg[i].global = global;
		global->thread_arg[i].first_group = 0;

		if (num_group && num_join) {
			/* Each thread joins only num_join groups, starting
			 * from this group index and wraping around the group
			 * table. */
			int first_group = (i * num_join) % num_group;

			global->thread_arg[i].first_group = first_group;
		}
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param,
				 num_cpu);

	if (ret != num_cpu) {
		printf("Error: thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static double measure_wait_time_cycles(uint64_t wait_ns)
{
	uint64_t i, c1, c2, diff;
	uint64_t rounds;
	double wait_cycles;

	if (wait_ns == 0)
		return 0.0;

	/* Run measurement for 100msec or at least two times, so that effect
	 * from CPU frequency scaling is minimized. */
	rounds = (100 * ODP_TIME_MSEC_IN_NS) / wait_ns;
	if (rounds == 0)
		rounds = 2;

	c1 = odp_cpu_cycles();

	for (i = 0; i < rounds; i++)
		odp_time_wait_ns(wait_ns);

	c2 = odp_cpu_cycles();
	diff = odp_cpu_cycles_diff(c2, c1);
	wait_cycles = (double)diff / rounds;

	printf("\nMeasured wait cycles: %.3f\n", wait_cycles);

	return wait_cycles;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double rounds_ave, enqueues_ave, events_ave, nsec_ave, cycles_ave;
	double waits_ave, wait_cycles, wait_cycles_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint64_t wait_ns = test_options->wait_ns;
	uint64_t rounds_sum = 0;
	uint64_t enqueues_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;
	uint64_t waits_sum = 0;

	wait_cycles = measure_wait_time_cycles(wait_ns);

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum   += global->stat[i].rounds;
		enqueues_sum += global->stat[i].enqueues;
		events_sum   += global->stat[i].events;
		nsec_sum     += global->stat[i].nsec;
		cycles_sum   += global->stat[i].cycles;
		waits_sum    += global->stat[i].waits;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return;
	}

	rounds_ave   = rounds_sum / num_cpu;
	enqueues_ave = enqueues_sum / num_cpu;
	events_ave   = events_sum / num_cpu;
	nsec_ave     = nsec_sum / num_cpu;
	cycles_ave   = cycles_sum / num_cpu;
	waits_ave    = waits_sum / num_cpu;
	wait_cycles_ave = waits_ave * wait_cycles;
	num = 0;

	printf("\n");
	printf("RESULTS - per thread (Million events per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (1000.0 * global->stat[i].events) /
			       global->stat[i].nsec);
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - average over %i threads:\n", num_cpu);
	printf("----------------------------------\n");
	printf("  schedule calls:           %.3f\n", rounds_ave);
	printf("  enqueue calls:            %.3f\n", enqueues_ave);
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  cycles per round:         %.3f\n",
	       cycles_ave / rounds_ave);
	printf("  cycles per event:         %.3f\n",
	       cycles_ave / events_ave);
	if (wait_ns) {
		printf("    without wait_ns cycles: %.3f\n",
		       (cycles_ave - wait_cycles_ave) / events_ave);
	}
	printf("  ave events received:      %.3f\n",
	       events_ave / rounds_ave);
	printf("  rounds per sec:           %.3f M\n",
	       (1000.0 * rounds_ave) / nsec_ave);
	printf("  events per sec:           %.3f M\n\n",
	       (1000.0 * events_ave) / nsec_ave);

	printf("TOTAL events per sec:       %.3f M\n\n",
	       (1000.0 * events_sum) / nsec_ave);
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;
	test_global_t *global;

	global = &test_global;
	memset(global, 0, sizeof(test_global_t));
	global->pool = ODP_POOL_INVALID;

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

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

	odp_schedule_config_init(&global->schedule_config);
	odp_schedule_config(&global->schedule_config);

	if (set_num_cpu(global))
		return -1;

	if (create_pool(global))
		return -1;

	if (create_groups(global))
		return -1;

	if (create_queues(global))
		return -1;

	/* Start workers */
	start_workers(global, instance);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->test_options.num_cpu);

	if (destroy_queues(global))
		return -1;

	if (destroy_groups(global))
		return -1;

	print_stat(global);

	if (odp_pool_destroy(global->pool)) {
		printf("Error: Pool destroy failed.\n");
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

	return 0;
}
