/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include <unistd.h>
#include <getopt.h>

#include <odp_api.h>

typedef struct test_global_t {
	struct {
		unsigned long long int period_ns;
		unsigned long long int res_ns;
		unsigned long long int offset_ns;
		int num;
		int init;
	} opt;

	odp_queue_t      queue;
	odp_timer_pool_t timer_pool;
	odp_pool_t       timeout_pool;
	odp_timer_t     *timer;
	uint64_t         period_ns;
	uint64_t         first_ns;

} test_global_t;

static void print_usage(void)
{
	printf("\n"
	       "Timer accuracy test application.\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -p, --period <nsec>     Timeout period in nsec. Default: 200 msec\n"
	       "  -r, --resolution <nsec> Timeout resolution in nsec. Default: period / 10\n"
	       "  -f, --first <nsec>      First timer offset in nsec. Default: 300 msec\n"
	       "  -n, --num <number>      Number of timeouts. Default: 50\n"
	       "  -i, --init              Set global init parameters. Default: init params not set.\n"
	       "  -h, --help              Display help and exit.\n\n");
}

static int parse_options(int argc, char *argv[], test_global_t *test_global)
{
	int opt, long_index;
	const struct option longopts[] = {
		{"period",     required_argument, NULL, 'p'},
		{"resolution", required_argument, NULL, 'r'},
		{"first",      required_argument, NULL, 'f'},
		{"num",        required_argument, NULL, 'n'},
		{"init",       no_argument,       NULL, 'i'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+p:r:f:n:ih";
	int ret = 0;

	test_global->opt.period_ns = 200 * ODP_TIME_MSEC_IN_NS;
	test_global->opt.res_ns    = 0;
	test_global->opt.offset_ns = 300 * ODP_TIME_MSEC_IN_NS;
	test_global->opt.num       = 50;
	test_global->opt.init      = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'p':
			test_global->opt.period_ns = strtoull(optarg, NULL, 0);
			break;
		case 'r':
			test_global->opt.res_ns = strtoull(optarg, NULL, 0);
			break;
		case 'f':
			test_global->opt.offset_ns = strtoull(optarg, NULL, 0);
			break;
		case 'n':
			test_global->opt.num = atoi(optarg);
			break;
		case 'i':
			test_global->opt.init = 1;
			break;
		case 'h':
			print_usage();
			ret = -1;
			break;
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_global->opt.res_ns == 0)
		test_global->opt.res_ns = test_global->opt.period_ns / 10;

	return ret;
}

static int start_timers(test_global_t *test_global)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_timer_pool_t timer_pool;
	odp_timer_pool_param_t timer_param;
	odp_timer_capability_t timer_capa;
	odp_timer_t timer;
	odp_queue_t queue;
	odp_queue_param_t queue_param;
	uint64_t tick, start_tick;
	uint64_t period_ns, res_ns, start_ns, nsec, res_capa, offset_ns;
	odp_event_t event;
	odp_timeout_t timeout;
	odp_timer_set_t ret;
	odp_time_t time;
	int i, num;

	num = test_global->opt.num;
	period_ns = test_global->opt.period_ns;
	test_global->period_ns = period_ns;

	/* Always init globals for destroy calls */
	test_global->queue = ODP_QUEUE_INVALID;
	test_global->timer_pool = ODP_TIMER_POOL_INVALID;
	test_global->timeout_pool = ODP_POOL_INVALID;

	for (i = 0; i < num; i++)
		test_global->timer[i] = ODP_TIMER_INVALID;

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	queue = odp_queue_create("timeout_queue", &queue_param);
	if (queue == ODP_QUEUE_INVALID) {
		printf("Queue create failed.\n");
		return -1;
	}

	test_global->queue = queue;

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = num;

	pool = odp_pool_create("timeout pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Timeout pool create failed.\n");
		return -1;
	}

	test_global->timeout_pool = pool;

	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa)) {
		printf("Timer capa failed\n");
		return -1;
	}

	res_capa = timer_capa.highest_res_ns;

	offset_ns = test_global->opt.offset_ns;
	res_ns = test_global->opt.res_ns;

	if (res_ns < res_capa) {
		printf("Resolution %" PRIu64 " nsec too high. "
		       "Highest resolution %" PRIu64 " nsec. "
		       "Default resolution is period / 10.\n\n",
		       res_ns, res_capa);
		return -1;
	}

	memset(&timer_param, 0, sizeof(odp_timer_pool_param_t));

	timer_param.res_ns     = res_ns;
	timer_param.min_tmo    = offset_ns / 2;
	timer_param.max_tmo    = offset_ns + ((num + 1) * period_ns);
	timer_param.num_timers = num;
	timer_param.clk_src    = ODP_CLOCK_CPU;

	printf("\nTest parameters:\n");
	printf("  resolution capa: %" PRIu64 " nsec\n", res_capa);
	printf("  start offset:    %" PRIu64 " nsec\n", offset_ns);
	printf("  period:          %" PRIu64 " nsec\n", period_ns);
	printf("  resolution:      %" PRIu64 " nsec\n", timer_param.res_ns);
	printf("  min timeout:     %" PRIu64 " nsec\n", timer_param.min_tmo);
	printf("  max timeout:     %" PRIu64 " nsec\n", timer_param.max_tmo);
	printf("  num timers:      %u\n", timer_param.num_timers);
	printf("  test run time:   %.1f sec\n\n",
	       timer_param.max_tmo / 1000000000.0);

	timer_pool = odp_timer_pool_create("timer_accuracy", &timer_param);

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		printf("Timer pool create failed\n");
		return -1;
	}

	odp_timer_pool_start();

	/* Spend some time so that current tick would not be zero */
	odp_time_wait_ns(100 * ODP_TIME_MSEC_IN_NS);

	test_global->timer_pool = timer_pool;

	for (i = 0; i < num; i++) {
		timer = odp_timer_alloc(timer_pool, queue, NULL);

		if (timer == ODP_TIMER_INVALID) {
			printf("Timer alloc failed.\n");
			return -1;
		}

		test_global->timer[i] = timer;
	}

	/* Run scheduler few times to ensure that (software) timer is active */
	for (i = 0; i < 1000; i++) {
		event = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (event != ODP_EVENT_INVALID) {
			printf("Spurious event received\n");
			odp_event_free(event);
			return -1;
		}
	}

	start_tick = odp_timer_current_tick(timer_pool);
	time       = odp_time_local();
	start_ns   = odp_time_to_ns(time);
	test_global->first_ns = start_ns + offset_ns;

	for (i = 0; i < num; i++) {
		timer = test_global->timer[i];

		timeout = odp_timeout_alloc(pool);
		if (timeout == ODP_TIMEOUT_INVALID) {
			printf("Timeout alloc failed\n");
			return -1;
		}

		event = odp_timeout_to_event(timeout);

		nsec = offset_ns + (i * period_ns);
		tick = start_tick + odp_timer_ns_to_tick(timer_pool, nsec);

		ret = odp_timer_set_abs(timer, tick, &event);

		if (ret != ODP_TIMER_SUCCESS) {
			printf("Timer[%i] set failed: ret %i\n", i, ret);
			return -1;
		}
	}

	return 0;
}

static int destroy_timers(test_global_t *test_global)
{
	int i, num;
	odp_timer_t timer;
	odp_event_t ev;
	int ret = 0;

	num = test_global->opt.num;

	for (i = 0; i < num; i++) {
		timer = test_global->timer[i];

		if (timer == ODP_TIMER_INVALID)
			break;

		ev = odp_timer_free(timer);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
	}

	if (test_global->timer_pool != ODP_TIMER_POOL_INVALID)
		odp_timer_pool_destroy(test_global->timer_pool);

	if (test_global->timeout_pool != ODP_POOL_INVALID) {
		if (odp_pool_destroy(test_global->timeout_pool)) {
			printf("Pool destroy failed.\n");
			ret = -1;
		}
	}

	if (test_global->queue != ODP_QUEUE_INVALID) {
		if (odp_queue_destroy(test_global->queue)) {
			printf("Queue destroy failed.\n");
			ret = -1;
		}
	}

	return ret;
}

static void run_test(test_global_t *test_global)
{
	int num, num_left;
	odp_event_t ev;
	odp_time_t time;
	uint64_t time_ns, diff_ns, next_tmo, res_ns;
	uint64_t after = 0;
	uint64_t min_after = UINT64_MAX;
	uint64_t max_after = 0;
	uint64_t before = 0;
	uint64_t min_before = UINT64_MAX;
	uint64_t max_before = 0;
	double ave_after = 0.0;
	double ave_before = 0.0;
	int num_after = 0;
	int num_exact = 0;
	int num_before = 0;

	res_ns = test_global->opt.res_ns;
	num = test_global->opt.num;
	num_left = num;
	next_tmo = test_global->first_ns;

	while (num_left) {
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);

		time = odp_time_local();
		time_ns = odp_time_to_ns(time);

		if (time_ns > next_tmo) {
			diff_ns = time_ns - next_tmo;
			num_after++;
			after += diff_ns;
			if (diff_ns < min_after)
				min_after = diff_ns;
			if (diff_ns > max_after)
				max_after = diff_ns;

		} else if (time_ns < next_tmo) {
			diff_ns = next_tmo - time_ns;
			num_before++;
			before += diff_ns;
			if (diff_ns < min_before)
				min_before = diff_ns;
			if (diff_ns > max_before)
				max_before = diff_ns;

		} else {
			num_exact++;
		}

		odp_event_free(ev);

		next_tmo += test_global->period_ns;
		num_left--;
	}

	/* Free current scheduler context. There should be no more events. */
	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT))
	       != ODP_EVENT_INVALID) {
		printf("Dropping extra event\n");
		odp_event_free(ev);
	}

	if (num_after)
		ave_after = (double)after / num_after;
	else
		min_after = 0;

	if (num_before)
		ave_before = (double)before / num_before;
	else
		min_before = 0;

	printf("\n Test results:\n");
	printf("  num after:  %12i  /  %.2f%%\n",
	       num_after, 100.0 * num_after / num);
	printf("  num before: %12i  /  %.2f%%\n",
	       num_before, 100.0 * num_before / num);
	printf("  num exact:  %12i  /  %.2f%%\n",
	       num_exact, 100.0 * num_exact / num);
	printf("  error after (nsec):\n");
	printf("         min: %12" PRIu64 "  /  %.3fx resolution\n",
	       min_after, (double)min_after / res_ns);
	printf("         max: %12" PRIu64 "  /  %.3fx resolution\n",
	       max_after, (double)max_after / res_ns);
	printf("         ave: %12.0f  /  %.3fx resolution\n",
	       ave_after, ave_after / res_ns);
	printf("  error before (nsec):\n");
	printf("         min: %12" PRIu64 "  /  %.3fx resolution\n",
	       min_before, (double)min_before / res_ns);
	printf("         max: %12" PRIu64 "  /  %.3fx resolution\n",
	       max_before, (double)max_before / res_ns);
	printf("         ave: %12.0f  /  %.3fx resolution\n",
	       ave_before, ave_before / res_ns);
	printf("\n");
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_init_t init;
	int num;
	test_global_t test_global;
	odp_init_t *init_ptr = NULL;
	int ret = 0;

	memset(&test_global, 0, sizeof(test_global_t));

	if (parse_options(argc, argv, &test_global))
		return -1;

	/* List features not to be used (may optimize performance) */
	odp_init_param_init(&init);
	init.not_used.feat.cls    = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec  = 1;
	init.not_used.feat.tm     = 1;

	if (test_global.opt.init)
		init_ptr = &init;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, init_ptr, NULL)) {
		printf("Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		printf("Local init failed.\n");
		return -1;
	}

	odp_sys_info_print();

	/* Configure scheduler */
	odp_schedule_config(NULL);

	num = test_global.opt.num;

	test_global.timer = calloc(num, sizeof(odp_timer_t));

	if (test_global.timer == NULL) {
		printf("Malloc failed.\n");
		goto quit;
	}

	if (start_timers(&test_global))
		goto quit;

	run_test(&test_global);

quit:
	if (destroy_timers(&test_global))
		ret = -1;

	if (test_global.timer)
		free(test_global.timer);

	if (odp_term_local()) {
		printf("Term local failed.\n");
		ret = -1;
	}

	if (odp_term_global(instance)) {
		printf("Term global failed.\n");
		ret = -1;
	}

	return ret;
}
