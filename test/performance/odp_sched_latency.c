/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_sched_latency.c  ODP scheduling latency benchmark application
 */

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* ODP main header */
#include <odp_api.h>

/* ODP helper for Linux apps */
#include <odp/helper/odph_api.h>

/* GNU lib C */
#include <getopt.h>

#define MAX_QUEUES	  4096		/**< Maximum number of queues */
#define MAX_GROUPS        64
#define EVENT_POOL_SIZE	  (1024 * 1024) /**< Event pool size */
#define TEST_ROUNDS	  10	/**< Test rounds for each thread (millions) */
#define MAIN_THREAD	  1	/**< Thread ID performing maintenance tasks */

/* Default values for command line arguments */
#define SAMPLE_EVENT_PER_PRIO	  0 /**< Allocate a separate sample event for
					 each priority */
#define HI_PRIO_EVENTS		  0 /**< Number of high priority events */
#define LO_PRIO_EVENTS		 32 /**< Number of low priority events */
#define HI_PRIO_QUEUES		 16 /**< Number of high priority queues */
#define LO_PRIO_QUEUES		 64 /**< Number of low priority queues */
#define WARM_UP_ROUNDS		100 /**< Number of warm-up rounds */

#define EVENTS_PER_HI_PRIO_QUEUE 0  /**< Alloc HI_PRIO_QUEUES x HI_PRIO_EVENTS
					 events */
#define EVENTS_PER_LO_PRIO_QUEUE 1  /**< Alloc LO_PRIO_QUEUES x LO_PRIO_EVENTS
					 events */
ODP_STATIC_ASSERT(HI_PRIO_QUEUES <= MAX_QUEUES, "Too many HI priority queues");
ODP_STATIC_ASSERT(LO_PRIO_QUEUES <= MAX_QUEUES, "Too many LO priority queues");

#define CACHE_ALIGN_ROUNDUP(x)\
	((ODP_CACHE_LINE_SIZE) * \
	 (((x) + ODP_CACHE_LINE_SIZE - 1) / (ODP_CACHE_LINE_SIZE)))

/* Test priorities */
#define NUM_PRIOS 2 /**< Number of tested priorities */
#define HI_PRIO	  0
#define LO_PRIO	  1

/* Test event forwarding mode */
#define EVENT_FORWARD_RAND 0
#define EVENT_FORWARD_INC  1
#define EVENT_FORWARD_NONE 2

/** Test event types */
typedef enum {
	WARM_UP,  /**< Warm-up event */
	COOL_DOWN,/**< Last event on queue */
	TRAFFIC,  /**< Event used only as traffic load */
	SAMPLE	  /**< Event used to measure latency */
} event_type_t;

/** Test event */
typedef struct {
	odp_time_t time_stamp;	/**< Send timestamp */
	event_type_t type;	/**< Message type */
	int src_idx[NUM_PRIOS]; /**< Source ODP queue */
	int prio;		/**< Source queue priority */
	int warm_up_rounds;	/**< Number of completed warm-up rounds */
} test_event_t;

/** Test arguments */
typedef struct {
	unsigned int cpu_count;	/**< CPU count */
	odp_schedule_sync_t sync_type;	/**< Scheduler sync type */
	int forward_mode;	/**< Event forwarding mode */
	int num_group;
	int isolate;
	int test_rounds;	/**< Number of test rounds (millions) */
	int warm_up_rounds;	/**< Number of warm-up rounds */
	struct {
		int queues;	/**< Number of scheduling queues */
		int events;	/**< Number of events */
		odp_bool_t events_per_queue; /**< Allocate 'queues' x 'events'
						  test events */
	} prio[NUM_PRIOS];
	odp_bool_t sample_per_prio; /**< Allocate a separate sample event for
					 each priority */
} test_args_t;

/** Latency measurements statistics */
typedef struct {
	uint64_t events;   /**< Total number of received events */
	uint64_t sample_events;  /**< Number of received sample events */
	uint64_t tot;	   /**< Total event latency. Sum of all events. */
	uint64_t min;	   /**< Minimum event latency */
	uint64_t max;	   /**< Maximum event latency */
	uint64_t max_idx;  /**< Index of the maximum latency sample event */
} test_stat_t;

/** Performance test statistics (per core) */
typedef struct ODP_ALIGNED_CACHE {
	test_stat_t prio[NUM_PRIOS]; /**< Test statistics per priority */
} core_stat_t;

/** Test global variables */
typedef struct {
	/** Core specific stats */
	core_stat_t	 core_stat[ODP_THREAD_COUNT_MAX];
	odp_barrier_t    barrier; /**< Barrier for thread synchronization */
	odp_pool_t       pool;	  /**< Pool for allocating test events */
	test_args_t      args;	  /**< Parsed command line arguments */
	odp_queue_t      queue[NUM_PRIOS][MAX_QUEUES]; /**< Scheduled queues */

	odp_schedule_group_t group[NUM_PRIOS][MAX_GROUPS];

} test_globals_t;

/**
 * Clear all scheduled queues.
 *
 * Use special cool_down event to guarantee that queue is drained.
 */
static void clear_sched_queues(test_globals_t *globals)
{
	odp_event_t ev;
	odp_buffer_t buf;
	test_event_t *event;
	int i, j;
	odp_queue_t fromq;

	/* Allocate the cool_down event. */
	buf = odp_buffer_alloc(globals->pool);
	if (buf == ODP_BUFFER_INVALID)
		ODPH_ABORT("Buffer alloc failed.\n");

	event = odp_buffer_addr(buf);
	event->type = COOL_DOWN;
	ev = odp_buffer_to_event(buf);

	for (i = 0; i < NUM_PRIOS; i++) {
		for (j = 0; j < globals->args.prio[i].queues; j++) {
			/* Enqueue cool_down event on each queue. */
			if (odp_queue_enq(globals->queue[i][j], ev))
				ODPH_ABORT("Queue enqueue failed.\n");

			/* Invoke scheduler until cool_down event has been
			 * received. */
			while (1) {
				ev = odp_schedule(NULL, ODP_SCHED_WAIT);
				buf = odp_buffer_from_event(ev);
				event = odp_buffer_addr(buf);
				if (event->type == COOL_DOWN)
					break;
				odp_event_free(ev);
			}
		}
	}

	/* Free the cool_down event. */
	odp_event_free(ev);

	/* Call odp_schedule() to trigger a release of any scheduler context. */
	ev = odp_schedule(&fromq, ODP_SCHED_NO_WAIT);
	if (ev != ODP_EVENT_INVALID)
		ODPH_ABORT("Queue %" PRIu64 " not empty.\n",
			   odp_queue_to_u64(fromq));
}

/**
 * Enqueue events into queues
 *
 * @param prio        Queue priority (HI_PRIO/LO_PRIO)
 * @param num_queues  Number of queues
 * @param num_events  Number of 'TRAFFIC' events
 * @param num_samples Number of 'SAMPLE' events
 * @param div_events  If true, divide 'num_events' between 'num_queues'. if
 *		      false, enqueue 'num_events' to each queue.
 * @param globals     Test shared data
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int enqueue_events(int prio, int num_queues, int num_events,
			  int num_samples, odp_bool_t div_events,
			  test_globals_t *globals)
{
	odp_buffer_t buf[num_events + num_samples];
	odp_event_t ev[num_events + num_samples];
	odp_queue_t queue;
	test_event_t *event;
	int i, j, ret;
	int enq_events;
	int events_per_queue;
	int tot_events;
	int rdy_events = 0;

	tot_events = num_events + num_samples;

	if (!num_queues || !tot_events)
		return 0;

	events_per_queue = tot_events;
	if (div_events)
		events_per_queue = (tot_events + num_queues - 1) / num_queues;

	for (i = 0; i < num_queues; i++) {
		queue = globals->queue[prio][i];

		ret = odp_buffer_alloc_multi(globals->pool, buf,
					     events_per_queue);
		if (ret != events_per_queue) {
			ODPH_ERR("Buffer alloc failed. Try increasing EVENT_POOL_SIZE.\n");
			ret = ret < 0 ? 0 : ret;
			odp_buffer_free_multi(buf, ret);
			return -1;
		}
		for (j = 0; j < events_per_queue; j++) {
			if (!odp_buffer_is_valid(buf[j])) {
				ODPH_ERR("Buffer alloc failed\n");
				odp_buffer_free_multi(buf, events_per_queue);
				return -1;
			}

			event = odp_buffer_addr(buf[j]);
			memset(event, 0, sizeof(test_event_t));

			/* Latency isn't measured from the first processing
			 * rounds. */
			if (num_samples > 0) {
				event->type = WARM_UP;
				event->warm_up_rounds = 0;
				num_samples--;
			} else {
				event->type = TRAFFIC;
			}
			event->src_idx[prio] = i;
			event->prio = prio;
			ev[j] = odp_buffer_to_event(buf[j]);
		}

		enq_events = 0;
		do {
			ret = odp_queue_enq_multi(queue, &ev[enq_events],
						  events_per_queue -
						  enq_events);
			if (ret < 0) {
				ODPH_ERR("Queue enqueue failed.\n");
				return -1;
			}
			enq_events += ret;
		} while (enq_events < events_per_queue);

		rdy_events += events_per_queue;
		if (div_events && rdy_events >= tot_events)
			return 0;
	}
	return 0;
}

/**
 * Print latency measurement results
 *
 * @param globals  Test shared data
 */
static void print_results(test_globals_t *globals)
{
	test_stat_t *lat;
	odp_schedule_sync_t stype;
	test_stat_t total;
	test_args_t *args;
	uint64_t avg;
	unsigned int i, j;

	args = &globals->args;
	stype = globals->args.sync_type;

	printf("\n%s queue scheduling latency\n",
	       (stype == ODP_SCHED_SYNC_ATOMIC) ? "ATOMIC" :
	       ((stype == ODP_SCHED_SYNC_ORDERED) ? "ORDERED" : "PARALLEL"));

	printf("  Forwarding mode: %s\n",
	       (args->forward_mode == EVENT_FORWARD_RAND) ? "random" :
	       ((args->forward_mode == EVENT_FORWARD_INC) ? "incremental" :
		"none"));

	printf("  LO_PRIO queues: %i\n", args->prio[LO_PRIO].queues);
	if (args->prio[LO_PRIO].events_per_queue)
		printf("  LO_PRIO event per queue: %i\n",
		       args->prio[LO_PRIO].events);
	else
		printf("  LO_PRIO events: %i\n", args->prio[LO_PRIO].events);

	printf("  HI_PRIO queues: %i\n", args->prio[HI_PRIO].queues);
	if (args->prio[HI_PRIO].events_per_queue)
		printf("  HI_PRIO event per queue: %i\n\n",
		       args->prio[HI_PRIO].events);
	else
		printf("  HI_PRIO events: %i\n\n", args->prio[HI_PRIO].events);

	for (i = 0; i < NUM_PRIOS; i++) {
		memset(&total, 0, sizeof(test_stat_t));
		total.min = UINT64_MAX;

		printf("%s priority\n"
		       "Thread   Avg[ns]    Min[ns]    Max[ns]    Samples    Total      Max idx\n"
		       "-----------------------------------------------------------------------\n",
		       i == HI_PRIO ? "HIGH" : "LOW");
		for (j = 1; j <= args->cpu_count; j++) {
			lat = &globals->core_stat[j].prio[i];

			if (lat->sample_events == 0) {
				printf("%-8d N/A\n", j);
				continue;
			}

			if (lat->max > total.max)
				total.max = lat->max;
			if (lat->min < total.min)
				total.min = lat->min;
			total.tot += lat->tot;
			total.sample_events += lat->sample_events;
			total.events += lat->events;

			avg = lat->events ? lat->tot / lat->sample_events : 0;
			printf("%-8d %-10" PRIu64 " %-10" PRIu64 " "
			       "%-10" PRIu64 " %-10" PRIu64 " %-10" PRIu64 " %-10" PRIu64 "\n",
			       j, avg, lat->min, lat->max, lat->sample_events,
			       lat->events, lat->max_idx);
		}
		printf("-----------------------------------------------------------------------\n");
		if (total.sample_events == 0) {
			printf("Total    N/A\n\n");
			continue;
		}
		avg = total.events ? total.tot / total.sample_events : 0;
		printf("Total    %-10" PRIu64 " %-10" PRIu64 " %-10" PRIu64 " "
		       "%-10" PRIu64 " %-10" PRIu64 "\n\n", avg, total.min,
		       total.max, total.sample_events, total.events);
	}
}

static int join_groups(test_globals_t *globals, int thr)
{
	odp_thrmask_t thrmask;
	odp_schedule_group_t group;
	int i, num;
	int num_group = globals->args.num_group;

	if (num_group <= 0)
		return 0;

	num = num_group;
	if (globals->args.isolate)
		num = 2 * num_group;

	odp_thrmask_zero(&thrmask);
	odp_thrmask_set(&thrmask, thr);

	for (i = 0; i < num; i++) {
		if (globals->args.isolate)
			group = globals->group[i % 2][i / 2];
		else
			group = globals->group[0][i];

		if (odp_schedule_group_join(group, &thrmask)) {
			ODPH_ERR("Group join failed %i (thr %i)\n", i, thr);
			return -1;
		}
	}

	return 0;
}

/**
 * Measure latency of scheduled ODP events
 *
 * Schedule and enqueue events until 'test_rounds' events have been processed.
 * Scheduling latency is measured only from type 'SAMPLE' events. Other events
 * are simply enqueued back to the scheduling queues.
 *
 * For 'TRAFFIC' type events the destination queue is selected from the same
 * priority class as source queue. 'SAMPLE' type event may change priority
 * depending on the command line arguments.
 *
 * @param thr      Thread ID
 * @param globals  Test shared data
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int test_schedule(int thr, test_globals_t *globals)
{
	odp_time_t time;
	odp_event_t ev;
	odp_buffer_t buf;
	odp_queue_t dst_queue;
	uint64_t latency;
	uint64_t i;
	test_event_t *event;
	test_stat_t *stats;
	int dst_idx, change_queue;
	int warm_up_rounds = globals->args.warm_up_rounds;
	uint64_t test_rounds = globals->args.test_rounds * (uint64_t)1000000;

	memset(&globals->core_stat[thr], 0, sizeof(core_stat_t));
	globals->core_stat[thr].prio[HI_PRIO].min = UINT64_MAX;
	globals->core_stat[thr].prio[LO_PRIO].min = UINT64_MAX;

	change_queue = globals->args.forward_mode != EVENT_FORWARD_NONE ? 1 : 0;

	odp_barrier_wait(&globals->barrier);

	for (i = 0; i < test_rounds; i++) {
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);

		time = odp_time_global_strict();

		buf = odp_buffer_from_event(ev);
		event = odp_buffer_addr(buf);

		stats = &globals->core_stat[thr].prio[event->prio];

		if (event->type == SAMPLE) {
			latency = odp_time_to_ns(time) - odp_time_to_ns(event->time_stamp);

			if (latency > stats->max) {
				stats->max = latency;
				stats->max_idx = stats->sample_events;
			}
			if (latency < stats->min)
				stats->min = latency;
			stats->tot += latency;
			stats->sample_events++;

			/* Move sample event to a different priority */
			if (!globals->args.sample_per_prio &&
			    globals->args.prio[!event->prio].queues)
				event->prio = !event->prio;
		}

		if (odp_unlikely(event->type == WARM_UP)) {
			event->warm_up_rounds++;
			if (event->warm_up_rounds >= warm_up_rounds)
				event->type = SAMPLE;
		} else {
			stats->events++;
		}

		/* Move event to next queue if forwarding is enabled */
		if (change_queue)
			dst_idx = event->src_idx[event->prio] + 1;
		else
			dst_idx = event->src_idx[event->prio];
		if (dst_idx >= globals->args.prio[event->prio].queues)
			dst_idx = 0;
		event->src_idx[event->prio] = dst_idx;
		dst_queue = globals->queue[event->prio][dst_idx];

		if (event->type == SAMPLE)
			event->time_stamp = odp_time_global_strict();

		if (odp_queue_enq(dst_queue, ev)) {
			ODPH_ERR("[%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	/* Clear possible locally stored buffers */
	odp_schedule_pause();

	while (1) {
		odp_queue_t src_queue;

		ev = odp_schedule(&src_queue, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		if (odp_queue_enq(src_queue, ev)) {
			ODPH_ERR("[%i] Queue enqueue failed.\n", thr);
			odp_event_free(ev);
			return -1;
		}
	}

	odp_barrier_wait(&globals->barrier);

	if (thr == MAIN_THREAD) {
		odp_schedule_resume();
		clear_sched_queues(globals);
		print_results(globals);
	}

	return 0;
}

/**
 * Worker thread
 *
 * @param arg  Arguments
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int run_thread(void *arg ODP_UNUSED)
{
	odp_shm_t shm;
	test_globals_t *globals;
	test_args_t *args;
	int thr;
	int sample_events = 0;

	thr = odp_thread_id();

	shm     = odp_shm_lookup("test_globals");
	globals = odp_shm_addr(shm);

	if (globals == NULL) {
		ODPH_ERR("Shared mem lookup failed\n");
		return -1;
	}

	if (join_groups(globals, thr))
		return -1;

	if (thr == MAIN_THREAD) {
		args = &globals->args;

		if (enqueue_events(HI_PRIO, args->prio[HI_PRIO].queues,
				   args->prio[HI_PRIO].events, 1,
				   !args->prio[HI_PRIO].events_per_queue,
				   globals))
			return -1;

		if (!args->prio[HI_PRIO].queues || args->sample_per_prio)
			sample_events = 1;

		if (enqueue_events(LO_PRIO, args->prio[LO_PRIO].queues,
				   args->prio[LO_PRIO].events, sample_events,
				   !args->prio[LO_PRIO].events_per_queue,
				   globals))
			return -1;
	}

	if (test_schedule(thr, globals))
		return -1;

	return 0;
}

/**
 * Print usage information
 */
static void usage(void)
{
	printf("\n"
	       "OpenDataPlane scheduler latency benchmark application.\n"
	       "\n"
	       "Usage: ./odp_sched_latency [options]\n"
	       "Optional OPTIONS:\n"
	       "  -c, --count <number> CPU count, 0=all available, default=1\n"
	       "  -d, --duration <number> Test duration in scheduling rounds (millions), default=%d, min=1\n"
	       "  -f, --forward-mode <mode> Selection of target queue\n"
	       "               0: Random (default)\n"
	       "               1: Incremental\n"
	       "               2: Use source queue\n"
	       "  -g, --num_group <num>  Number of schedule groups. Round robins queues into groups.\n"
	       "                         -1: SCHED_GROUP_WORKER\n"
	       "                          0: SCHED_GROUP_ALL (default)\n"
	       "  -i, --isolate <mode> Select if shared or isolated groups are used. Ignored when num_group <= 0.\n"
	       "                       0: All queues share groups (default)\n"
	       "                       1: Separate groups for high and low priority queues. Creates 2xnum_group groups.\n"
	       "  -l, --lo-prio-queues <number> Number of low priority scheduled queues\n"
	       "  -t, --hi-prio-queues <number> Number of high priority scheduled queues\n"
	       "  -m, --lo-prio-events-per-queue <number> Number of events per low priority queue\n"
	       "  -n, --hi-prio-events-per-queue <number> Number of events per high priority queues\n"
	       "  -o, --lo-prio-events <number> Total number of low priority events (overrides the\n"
	       "				number of events per queue)\n"
	       "  -p, --hi-prio-events <number> Total number of high priority events (overrides the\n"
	       "				number of events per queue)\n"
	       "  -r  --sample-per-prio Allocate a separate sample event for each priority. By default\n"
	       "			a single sample event is used and its priority is changed after\n"
	       "			each processing round.\n"
	       "  -s, --sync  Scheduled queues' sync type\n"
	       "               0: ODP_SCHED_SYNC_PARALLEL (default)\n"
	       "               1: ODP_SCHED_SYNC_ATOMIC\n"
	       "               2: ODP_SCHED_SYNC_ORDERED\n"
	       "  -w, --warm-up <number> Number of warm-up rounds, default=%d, min=1\n"
	       "  -h, --help   Display help and exit.\n\n"
	       , TEST_ROUNDS, WARM_UP_ROUNDS);
}

/**
 * Parse arguments
 *
 * @param argc  Argument count
 * @param argv  Argument vector
 * @param args  Test arguments
 */
static void parse_args(int argc, char *argv[], test_args_t *args)
{
	int opt;
	int long_index;
	int i;

	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"duration", required_argument, NULL, 'd'},
		{"forward-mode", required_argument, NULL, 'f'},
		{"num_group", required_argument, NULL, 'g'},
		{"isolate", required_argument, NULL, 'i'},
		{"lo-prio-queues", required_argument, NULL, 'l'},
		{"hi-prio-queues", required_argument, NULL, 't'},
		{"lo-prio-events-per-queue", required_argument, NULL, 'm'},
		{"hi-prio-events-per-queue", required_argument, NULL, 'n'},
		{"lo-prio-events", required_argument, NULL, 'o'},
		{"hi-prio-events", required_argument, NULL, 'p'},
		{"sync", required_argument, NULL, 's'},
		{"warm-up", required_argument, NULL, 'w'},
		{"sample-per-prio", no_argument, NULL, 'r'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:d:f:g:i:l:t:m:n:o:p:s:w:rh";

	args->cpu_count = 1;
	args->forward_mode = EVENT_FORWARD_RAND;
	args->num_group = 0;
	args->isolate = 0;
	args->test_rounds = TEST_ROUNDS;
	args->warm_up_rounds = WARM_UP_ROUNDS;
	args->sync_type = ODP_SCHED_SYNC_PARALLEL;
	args->sample_per_prio = SAMPLE_EVENT_PER_PRIO;
	args->prio[LO_PRIO].queues = LO_PRIO_QUEUES;
	args->prio[HI_PRIO].queues = HI_PRIO_QUEUES;
	args->prio[LO_PRIO].events = LO_PRIO_EVENTS;
	args->prio[HI_PRIO].events = HI_PRIO_EVENTS;
	args->prio[LO_PRIO].events_per_queue = EVENTS_PER_LO_PRIO_QUEUE;
	args->prio[HI_PRIO].events_per_queue = EVENTS_PER_HI_PRIO_QUEUE;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			args->cpu_count = atoi(optarg);
			break;
		case 'd':
			args->test_rounds = atoi(optarg);
			break;
		case 'f':
			args->forward_mode = atoi(optarg);
			break;
		case 'g':
			args->num_group = atoi(optarg);
			break;
		case 'i':
			args->isolate = atoi(optarg);
			break;
		case 'l':
			args->prio[LO_PRIO].queues = atoi(optarg);
			break;
		case 't':
			args->prio[HI_PRIO].queues = atoi(optarg);
			break;
		case 'm':
			args->prio[LO_PRIO].events = atoi(optarg);
			args->prio[LO_PRIO].events_per_queue = 1;
			break;
		case 'n':
			args->prio[HI_PRIO].events = atoi(optarg);
			args->prio[HI_PRIO].events_per_queue = 1;
			break;
		case 'o':
			args->prio[LO_PRIO].events = atoi(optarg);
			args->prio[LO_PRIO].events_per_queue = 0;
			break;
		case 'p':
			args->prio[HI_PRIO].events = atoi(optarg);
			args->prio[HI_PRIO].events_per_queue = 0;
			break;
		case 's':
			i = atoi(optarg);
			if (i == 1)
				args->sync_type = ODP_SCHED_SYNC_ATOMIC;
			else if (i == 2)
				args->sync_type = ODP_SCHED_SYNC_ORDERED;
			else
				args->sync_type = ODP_SCHED_SYNC_PARALLEL;
			break;
		case 'r':
			args->sample_per_prio = 1;
			break;
		case 'w':
			args->warm_up_rounds = atoi(optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	/* Make sure arguments are valid */
	/* -1 for main thread */
	if (args->cpu_count > ODP_THREAD_COUNT_MAX - 1)
		args->cpu_count = ODP_THREAD_COUNT_MAX - 1;
	if (args->prio[LO_PRIO].queues > MAX_QUEUES)
		args->prio[LO_PRIO].queues = MAX_QUEUES;
	if (args->prio[HI_PRIO].queues > MAX_QUEUES)
		args->prio[HI_PRIO].queues = MAX_QUEUES;
	if (args->test_rounds < 1)
		args->test_rounds = 1;
	if (!args->prio[HI_PRIO].queues && !args->prio[LO_PRIO].queues) {
		printf("No queues configured\n");
		usage();
		exit(EXIT_FAILURE);
	}
	if (args->forward_mode > EVENT_FORWARD_NONE ||
	    args->forward_mode < EVENT_FORWARD_RAND) {
		printf("Invalid forwarding mode\n");
		usage();
		exit(EXIT_FAILURE);
	}

	if (args->num_group > MAX_GROUPS) {
		ODPH_ERR("Too many groups. Max supported %i.\n", MAX_GROUPS);
		exit(EXIT_FAILURE);
	}
}

static void randomize_queues(odp_queue_t queues[], uint32_t num, uint64_t *seed)
{
	uint32_t i;

	for (i = 0; i < num; i++) {
		uint32_t new_index;
		odp_queue_t swap_queue;
		odp_queue_t cur_queue = queues[i];

		odp_random_test_data((uint8_t *)&new_index, sizeof(new_index),
				     seed);
		new_index = new_index % num;
		swap_queue = queues[new_index];

		queues[new_index] = cur_queue;
		queues[i] = swap_queue;
	}
}

static int create_groups(test_globals_t *globals, odp_schedule_group_t group[], int num)
{
	odp_schedule_capability_t sched_capa;
	odp_thrmask_t zeromask;
	int i, j, max;

	if (num <= 0)
		return 0;

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Schedule capability failed\n");
		return 0;
	}

	max = sched_capa.max_groups - 3;
	if (num > max) {
		printf("Too many schedule groups %i (max %u)\n", num, max);
		return 0;
	}

	for (i = 0; i < NUM_PRIOS; i++)
		for (j = 0; j < MAX_GROUPS; j++)
			globals->group[i][j] = ODP_SCHED_GROUP_INVALID;

	odp_thrmask_zero(&zeromask);

	for (i = 0; i < num; i++) {
		group[i] = odp_schedule_group_create("test_group", &zeromask);

		if (group[i] == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("Group create failed %i\n", i);
			break;
		}

		if (globals->args.isolate) {
			globals->group[i % 2][i / 2] = group[i];
		} else {
			globals->group[0][i] = group[i];
			globals->group[1][i] = group[i];
		}
	}

	return i;
}

static int destroy_groups(odp_schedule_group_t group[], int num)
{
	int i;

	if (num <= 0)
		return 0;

	for (i = 0; i < num; i++) {
		if (odp_schedule_group_destroy(group[i])) {
			ODPH_ERR("Group destroy failed %i\n", i);
			return -1;
		}
	}

	return 0;
}

/**
 * Test main function
 */
int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_init_t init_param;
	odph_helper_options_t helper_options;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_cpumask_t cpumask;
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;
	test_globals_t *globals;
	test_args_t args;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	uint32_t pool_size;
	int i, j, ret;
	int num_group, tot_group;
	odp_schedule_group_t group[2 * MAX_GROUPS];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	int err = 0;
	int num_workers = 0;
	odp_shm_t shm = ODP_SHM_INVALID;
	odp_pool_t pool = ODP_POOL_INVALID;

	printf("\nODP scheduling latency benchmark starts\n\n");

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	memset(&args, 0, sizeof(args));
	parse_args(argc, argv, &args);

	/* ODP global init */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	num_group = args.num_group;

	tot_group = 0;
	if (num_group > 0)
		tot_group = args.isolate ? 2 * num_group : num_group;

	/* Get default worker cpumask */
	if (args.cpu_count)
		num_workers = args.cpu_count;

	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	args.cpu_count = num_workers;

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("Test options:\n");
	printf("  Worker threads:   %i\n", num_workers);
	printf("  First CPU:        %i\n", odp_cpumask_first(&cpumask));
	printf("  CPU mask:         %s\n", cpumaskstr);
	printf("  Test rounds:      %iM\n", args.test_rounds);
	printf("  Warm-up rounds:   %i\n", args.warm_up_rounds);
	printf("  Isolated groups:  %i\n", args.isolate);
	printf("  Number of groups: %i\n", num_group);
	printf("  Created groups:   %i\n", tot_group);
	printf("\n");

	shm = odp_shm_reserve("test_globals", sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed.\n");
		err = -1;
		goto error;
	}

	globals = odp_shm_addr(shm);
	memset(globals, 0, sizeof(test_globals_t));
	memcpy(&globals->args, &args, sizeof(test_args_t));

	odp_schedule_config(NULL);

	/*
	 * Create event pool
	 */
	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("pool capa failed\n");
		err = -1;
		goto error;
	}

	pool_size = EVENT_POOL_SIZE;
	if (pool_capa.buf.max_num && pool_capa.buf.max_num < EVENT_POOL_SIZE)
		pool_size = pool_capa.buf.max_num;

	odp_pool_param_init(&params);
	params.buf.size  = sizeof(test_event_t);
	params.buf.align = 0;
	params.buf.num   = pool_size;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("event_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed.\n");
		err = -1;
		goto error;
	}
	globals->pool = pool;

	/* Create groups */
	ret = create_groups(globals, group, tot_group);
	if (ret != tot_group) {
		ODPH_ERR("Group create failed.\n");
		tot_group = ret;
		err = -1;
		goto error;
	}

	/*
	 * Create queues for schedule test
	 */
	for (i = 0; i < NUM_PRIOS; i++) {
		char name[] = "sched_XX_YY";
		odp_queue_t queue;
		odp_queue_param_t param;
		odp_schedule_group_t grp;
		int prio;

		grp = ODP_SCHED_GROUP_ALL;
		if (num_group < 0)
			grp = ODP_SCHED_GROUP_WORKER;

		if (i == HI_PRIO)
			prio = odp_schedule_max_prio();
		else
			prio = odp_schedule_min_prio();

		name[6] = '0' + (prio / 10);
		name[7] = '0' + prio - (10 * (prio / 10));

		odp_queue_param_init(&param);
		param.type        = ODP_QUEUE_TYPE_SCHED;
		param.sched.prio  = prio;
		param.sched.sync  = args.sync_type;

		for (j = 0; j < args.prio[i].queues; j++) {
			name[9]  = '0' + j / 10;
			name[10] = '0' + j - 10 * (j / 10);

			/* Round robin queues into groups */
			if (num_group > 0)
				grp = globals->group[i][j % num_group];

			param.sched.group = grp;

			queue = odp_queue_create(name, &param);

			if (queue == ODP_QUEUE_INVALID) {
				ODPH_ERR("Scheduled queue create failed.\n");
				exit(EXIT_FAILURE);
			}

			globals->queue[i][j] = queue;
		}
		if (args.forward_mode == EVENT_FORWARD_RAND) {
			uint64_t seed = i;

			randomize_queues(globals->queue[i], args.prio[i].queues,
					 &seed);
		}
	}

	odp_barrier_init(&globals->barrier, num_workers);

	/* Create and launch worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = run_thread;
	thr_param.arg = NULL;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers);

	/* Wait for worker threads to terminate */
	odph_thread_join(thread_tbl, num_workers);

	printf("ODP scheduling latency test complete\n\n");

	for (i = 0; i < NUM_PRIOS; i++) {
		odp_queue_t queue;
		int num_queues;

		num_queues = args.prio[i].queues;

		for (j = 0; j < num_queues; j++) {
			queue = globals->queue[i][j];
			if (odp_queue_destroy(queue)) {
				ODPH_ERR("Queue destroy failed [%i][%i]\n", i, j);
				err = -1;
				break;
			}
		}
	}

error:
	if (destroy_groups(group, tot_group)) {
		ODPH_ERR("Group destroy failed\n");
		err = -1;
	}

	if (pool != ODP_POOL_INVALID) {
		if (odp_pool_destroy(pool)) {
			ODPH_ERR("Pool destroy failed\n");
			err = -1;
		}
	}

	if (shm != ODP_SHM_INVALID) {
		if (odp_shm_free(shm)) {
			ODPH_ERR("SHM destroy failed\n");
			err = -1;
		}
	}

	err += odp_term_local();
	err += odp_term_global(instance);

	return err;
}
