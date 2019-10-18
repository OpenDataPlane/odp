/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <strings.h>
#include <errno.h>
#include <stdio.h>

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            (ODP_THREAD_COUNT_MAX - 1)

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (512*2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PMR_COUNT
 * @brief Maximum number of Classification Policy
 */
#define MAX_PMR_COUNT	8

/** @def DISPLAY_STRING_LEN
 * @brief Length of string used to display term value
 */
#define DISPLAY_STRING_LEN	32

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
		strrchr((file_name), '/') + 1 : (file_name))

typedef struct {
	odp_queue_t queue;	/**< Associated queue handle */
	odp_pool_t pool;	/**< Associated pool handle */
	odp_cos_t cos;		/**< Associated cos handle */
	odp_pmr_t pmr;		/**< Associated pmr handle */
	odp_atomic_u64_t queue_pkt_count; /**< count of received packets */
	odp_atomic_u64_t pool_pkt_count; /**< count of received packets */
	char cos_name[ODP_COS_NAME_LEN];	/**< cos name */
	char src_cos_name[ODP_COS_NAME_LEN];	/**< source cos name */
	struct {
		odp_cls_pmr_term_t term;	/**< odp pmr term value */
		uint64_t val;	/**< pmr term value */
		uint64_t mask;	/**< pmr term mask */
		uint32_t val_sz;	/**< size of the pmr term */
		uint32_t offset;	/**< pmr term offset */
	} rule;
	char value[DISPLAY_STRING_LEN];	/**< Display string for value */
	char mask[DISPLAY_STRING_LEN];	/**< Display string for mask */
	int has_src_cos;

} global_statistics;

typedef struct {
	global_statistics stats[MAX_PMR_COUNT];
	int policy_count;	/**< global policy count */
	int appl_mode;		/**< application mode */
	odp_atomic_u64_t total_packets;	/**< total received packets */
	unsigned int cpu_count; /**< Number of CPUs to use */
	uint32_t time;		/**< Number of seconds to run */
	char *if_name;		/**< pointer to interface names */
	int shutdown;		/**< Shutdown threads if !0 */
	int shutdown_sig;
	int verbose;
} appl_args_t;

enum packet_mode {
	APPL_MODE_DROP,		/**< Packet is dropped */
	APPL_MODE_REPLY		/**< Packet is sent back */
};

static appl_args_t *appl_args_gbl;

static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

static inline void print_cls_statistics(appl_args_t *args)
{
	int i;
	uint32_t timeout;
	int infinite = 0;

	printf("\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	/* print statistics */
	printf("CLASSIFIER EXAMPLE STATISTICS\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	printf("CONFIGURATION\n");
	printf("\n");
	printf("COS\tVALUE\t\tMASK\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	for (i = 0; i < args->policy_count - 1; i++) {
		printf("%s\t", args->stats[i].cos_name);
		printf("%s\t", args->stats[i].value);
		printf("%s\n", args->stats[i].mask);
	}
	printf("\n");
	printf("RECEIVED PACKETS\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	for (i = 0; i < args->policy_count; i++)
		printf("%-12s |", args->stats[i].cos_name);
	printf("Total Packets");
	printf("\n");
	for (i = 0; i < args->policy_count; i++)
		printf("%-6s %-6s|", "queue", "pool");
	printf("\n");

	timeout = args->time;

	/* Incase if default value is given for timeout
	run the loop infinitely */
	if (timeout == 0)
		infinite = 1;

	for (; timeout > 0 || infinite; timeout--) {
		for (i = 0; i < args->policy_count; i++) {
			printf("%-6" PRIu64 " ",
			       odp_atomic_load_u64(&args->stats[i]
						   .queue_pkt_count));
			printf("%-6" PRIu64 "|",
			       odp_atomic_load_u64(&args->stats[i]
						   .pool_pkt_count));
		}

		printf("%-" PRIu64, odp_atomic_load_u64(&args->
							total_packets));

		if (args->shutdown_sig)
			break;

		sleep(1);
		printf("\r");
		fflush(stdout);
	}

	printf("\n");
}

static inline int parse_mask(const char *str, uint64_t *mask)
{
	uint64_t b;
	int ret;

	ret = sscanf(str, "%" SCNx64, &b);
	*mask = b;
	return ret != 1;
}

static int parse_value(const char *str, uint64_t *val, uint32_t *val_sz)
{
	size_t len;
	size_t i;
	int converted;
	union {
		uint64_t u64;
		uint8_t u8[8];
	} buf = {.u64 = 0};

	len = strlen(str);
	if (len > 2 * sizeof(buf))
		return -1;

	for (i = 0; i < len; i += 2) {
		converted = sscanf(&str[i], "%2" SCNx8, &buf.u8[i / 2]);
		if (1 != converted)
			return -1;
	}

	*val = buf.u64;
	*val_sz = len / 2;
	return 0;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Device name
 * @param pool Associated Packet Pool
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		if (odp_errno() == EPERM)
			ODPH_ERR("Root level permission required\n");

		ODPH_ERR("pktio create failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	pktin_param.classifier_enable = 1;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		ODPH_ERR("pktin queue config failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	if (odp_pktout_queue_config(pktio, NULL)) {
		ODPH_ERR("pktout queue config failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	printf("  created pktio:%02" PRIu64
			", dev:%s, queue mode (ATOMIC queues)\n"
			"  \tdefault pktio%02" PRIu64 "\n",
			odp_pktio_to_u64(pktio), dev,
			odp_pktio_to_u64(pktio));

	return pktio;
}

/**
 * Worker threads to receive the packet
 *
 */
static int pktio_receive_thread(void *arg)
{
	int thr;
	odp_pktout_queue_t pktout;
	odp_packet_t pkt;
	odp_pool_t pool;
	odp_event_t ev;
	odp_queue_t queue;
	int i;
	global_statistics *stats;
	unsigned long err_cnt = 0;
	thr = odp_thread_id();
	appl_args_t *appl = (appl_args_t *)arg;
	uint64_t wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;

		if (appl->shutdown)
			break;

		/* Use schedule to get buf from any input queue */
		ev = odp_schedule(&queue, wait_time);

		/* Loop back to receive packets incase of invalid event */
		if (odp_unlikely(ev == ODP_EVENT_INVALID))
			continue;

		pkt = odp_packet_from_event(ev);

		if (appl->verbose) {
			odp_queue_info_t info;
			uint32_t len = odp_packet_len(pkt);

			if (odp_queue_info(queue, &info) == 0)
				printf("Queue: %s\n", info.name);

			if (len > 96)
				len = 96;

			odp_packet_print_data(pkt, 0, len);
		}

		/* Total packets received */
		odp_atomic_inc_u64(&appl->total_packets);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			ODPH_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

		pktio_tmp = odp_packet_input(pkt);

		if (odp_pktout_queue(pktio_tmp, &pktout, 1) != 1) {
			ODPH_ERR("  [%02i] Error: no output queue\n", thr);
			return -1;
		}

		pool = odp_packet_pool(pkt);

		/* Swap Eth MACs and possibly IP-addrs before sending back */
		swap_pkt_addrs(&pkt, 1);
		for (i = 0; i <  MAX_PMR_COUNT; i++) {
			stats = &appl->stats[i];
			if (queue == stats->queue)
				odp_atomic_inc_u64(&stats->queue_pkt_count);
			if (pool == stats->pool)
				odp_atomic_inc_u64(&stats->pool_pkt_count);
		}

		if (appl->appl_mode == APPL_MODE_DROP) {
			odp_packet_free(pkt);
			continue;
		}

		if (odp_pktout_send(pktout, &pkt, 1) < 1) {
			ODPH_ERR("  [%i] Packet send failed\n", thr);
			odp_packet_free(pkt);
		}
	}

	return 0;
}

static odp_cos_t configure_default_cos(odp_pktio_t pktio, appl_args_t *args)
{
	odp_queue_param_t qparam;
	const char *queue_name = "DefaultQueue";
	const char *pool_name = "DefaultPool";
	const char *cos_name = "DefaultCos";
	odp_queue_t queue_default;
	odp_pool_t pool_default;
	odp_cos_t cos_default;
	odp_pool_param_t pool_params;
	odp_cls_cos_param_t cls_param;
	global_statistics *stats = args->stats;


	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	queue_default = odp_queue_create(queue_name, &qparam);
	if (queue_default == ODP_QUEUE_INVALID) {
		ODPH_ERR("Error: default queue create failed\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_param_init(&pool_params);
	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	pool_params.type        = ODP_POOL_PACKET;
	pool_default = odp_pool_create(pool_name, &pool_params);

	if (pool_default == ODP_POOL_INVALID) {
		ODPH_ERR("Error: default pool create failed\n");
		exit(EXIT_FAILURE);
	}

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_default;
	cls_param.queue = queue_default;
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_default = odp_cls_cos_create(cos_name, &cls_param);

	if (cos_default == ODP_COS_INVALID) {
		ODPH_ERR("Error: default cos create failed\n");
		exit(EXIT_FAILURE);
	}

	if (0 > odp_pktio_default_cos_set(pktio, cos_default)) {
		ODPH_ERR("odp_pktio_default_cos_set failed\n");
		exit(EXIT_FAILURE);
	}
	stats[args->policy_count].cos = cos_default;
	/* add default queue to global stats */
	stats[args->policy_count].queue = queue_default;
	stats[args->policy_count].pool = pool_default;
	snprintf(stats[args->policy_count].cos_name,
		 sizeof(stats[args->policy_count].cos_name),
		 "%s", cos_name);
	odp_atomic_init_u64(&stats[args->policy_count].queue_pkt_count, 0);
	odp_atomic_init_u64(&stats[args->policy_count].pool_pkt_count, 0);
	args->policy_count++;
	return cos_default;
}

static int find_cos(appl_args_t *args, const char *name, odp_cos_t *cos)
{
	global_statistics *stats;
	int i;

	for (i = 0; i < args->policy_count - 1; i++) {
		stats = &args->stats[i];

		if (strcmp(stats->cos_name, name) == 0) {
			*cos = stats->cos;
			return 0;
		}
	}

	return -1;
}

static void configure_cos(odp_cos_t default_cos, appl_args_t *args)
{
	char cos_name[ODP_COS_NAME_LEN];
	char pool_name[ODP_POOL_NAME_LEN];
	const char *queue_name;
	odp_pool_param_t pool_params;
	odp_cls_cos_param_t cls_param;
	int i;
	global_statistics *stats;
	odp_queue_param_t qparam;

	for (i = 0; i < args->policy_count - 1; i++) {
		stats = &args->stats[i];

		odp_queue_param_init(&qparam);
		qparam.type       = ODP_QUEUE_TYPE_SCHED;
		qparam.sched.prio = i % odp_schedule_num_prio();
		qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;

		queue_name = args->stats[i].cos_name;
		stats->queue = odp_queue_create(queue_name, &qparam);
		if (ODP_QUEUE_INVALID == stats->queue) {
			ODPH_ERR("odp_queue_create failed\n");
			exit(EXIT_FAILURE);
		}

		odp_pool_param_init(&pool_params);
		pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
		pool_params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
		pool_params.pkt.num     = SHM_PKT_POOL_SIZE /
					SHM_PKT_POOL_BUF_SIZE;
		pool_params.type        = ODP_POOL_PACKET;

		snprintf(pool_name, sizeof(pool_name), "%sPool%d",
			 args->stats[i].cos_name, i);
		stats->pool = odp_pool_create(pool_name, &pool_params);

		if (stats->pool == ODP_POOL_INVALID) {
			ODPH_ERR("Error: default pool create failed\n");
			exit(EXIT_FAILURE);
		}

		snprintf(cos_name, sizeof(cos_name), "CoS%s",
			 stats->cos_name);
		odp_cls_cos_param_init(&cls_param);
		cls_param.pool = stats->pool;
		cls_param.queue = stats->queue;
		cls_param.drop_policy = ODP_COS_DROP_POOL;
		stats->cos = odp_cls_cos_create(cos_name, &cls_param);

		odp_atomic_init_u64(&stats->queue_pkt_count, 0);
		odp_atomic_init_u64(&stats->pool_pkt_count, 0);
	}

	for (i = 0; i < args->policy_count - 1; i++) {
		odp_pmr_param_t pmr_param;
		odp_cos_t src_cos = default_cos;

		stats = &args->stats[i];

		if (stats->has_src_cos) {
			if (find_cos(args, stats->src_cos_name, &src_cos)) {
				ODPH_ERR("find_cos failed\n");
				exit(EXIT_FAILURE);
			}
		}

		odp_cls_pmr_param_init(&pmr_param);
		pmr_param.term = stats->rule.term;
		pmr_param.match.value = &stats->rule.val;
		pmr_param.match.mask = &stats->rule.mask;
		pmr_param.val_sz = stats->rule.val_sz;
		pmr_param.offset = stats->rule.offset;

		stats->pmr = odp_cls_pmr_create(&pmr_param, 1, src_cos,
						stats->cos);
		if (stats->pmr == ODP_PMR_INVALID) {
			ODPH_ERR("odp_pktio_pmr_cos failed\n");
			exit(EXIT_FAILURE);
		}
	}

}

static void sig_handler(int signo)
{
	(void)signo;

	if (appl_args_gbl == NULL)
		return;
	appl_args_gbl->shutdown_sig = 1;
}

/**
 * ODP Classifier example main function
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int num_workers;
	int i;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_pktio_t pktio;
	appl_args_t *args;
	odp_cos_t default_cos;
	odp_shm_t shm;
	int ret;
	odp_instance_t instance;
	odp_init_t init_param;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;

	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("cls_shm_args", sizeof(appl_args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed\n");
		exit(EXIT_FAILURE);
	}

	args = odp_shm_addr(shm);

	if (args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	appl_args_gbl = args;
	memset(args, 0, sizeof(*args));
	/* Parse and store the application arguments */
	parse_args(argc, argv, args);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), args);

	num_workers = MAX_WORKERS;
	if (args->cpu_count && args->cpu_count < MAX_WORKERS)
		num_workers = args->cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed\n");
		exit(EXIT_FAILURE);
	}

	/* Configure scheduler */
	odp_schedule_config(NULL);

	/* odp_pool_print(pool); */
	odp_atomic_init_u64(&args->total_packets, 0);

	/* create pktio per interface */
	pktio = create_pktio(args->if_name, pool);

	/* configure default Cos */
	default_cos = configure_default_cos(pktio, args);

	configure_cos(default_cos, args);

	if (odp_pktio_start(pktio)) {
		ODPH_ERR("Error: unable to start pktio\n");
		exit(EXIT_FAILURE);
	}

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(&thr_common, 0, sizeof(thr_common));
	memset(&thr_param, 0, sizeof(thr_param));

	thr_param.start    = pktio_receive_thread;
	thr_param.arg      = args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	thr_common.instance    = instance;
	thr_common.cpumask     = &cpumask;
	thr_common.share_param = 1;

	odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers);

	if (args->verbose == 0) {
		print_cls_statistics(args);
	} else {
		int timeout = args->time;

		for (i = 0; timeout == 0 || i < timeout; i++) {
			if (args->shutdown_sig)
				break;

			sleep(1);
		}
	}

	odp_pktio_stop(pktio);
	args->shutdown = 1;
	odph_thread_join(thread_tbl, num_workers);

	for (i = 0; i < args->policy_count; i++) {
		if ((i !=  args->policy_count - 1) &&
		    odp_cls_pmr_destroy(args->stats[i].pmr))
			ODPH_ERR("err: odp_cls_pmr_destroy for %d\n", i);
		if (odp_cos_destroy(args->stats[i].cos))
			ODPH_ERR("err: odp_cos_destroy for %d\n", i);
		if (odp_queue_destroy(args->stats[i].queue))
			ODPH_ERR("err: odp_queue_destroy for %d\n", i);
		if (odp_pool_destroy(args->stats[i].pool))
			ODPH_ERR("err: odp_pool_destroy for %d\n", i);
	}

	free(args->if_name);
	odp_shm_free(shm);
	if (odp_pktio_close(pktio))
		ODPH_ERR("err: close pktio error\n");
	if (odp_pool_destroy(pool))
		ODPH_ERR("err: odp_pool_destroy error\n");

	ret = odp_term_local();
	if (ret)
		ODPH_ERR("odp_term_local error %d\n", ret);
	ret = odp_term_global(instance);
	if (ret)
		ODPH_ERR("odp_term_global error %d\n", ret);
	printf("Exit\n\n");
	return ret;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return pkt_cnt;
}

/**
 * Swap eth src<->dst and IP src<->dst addresses
 *
 * @param pkt_tbl  Array of packets
 * @param len      Length of pkt_tbl[]
 */
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ethaddr_t tmp_addr;
	odph_ipv4hdr_t *ip;
	odp_u32be_t ip_tmp_addr; /* tmp ip addr */
	unsigned i;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		if (odp_packet_has_eth(pkt)) {
			eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

			tmp_addr = eth->dst;
			eth->dst = eth->src;
			eth->src = tmp_addr;

			if (odp_packet_has_ipv4(pkt)) {
				/* IPv4 */
				ip = (odph_ipv4hdr_t *)
					odp_packet_l3_ptr(pkt, NULL);

				ip_tmp_addr  = ip->src_addr;
				ip->src_addr = ip->dst_addr;
				ip->dst_addr = ip_tmp_addr;
			}
		}
	}
}

static int convert_str_to_pmr_enum(char *token, odp_cls_pmr_term_t *term)
{
	if (NULL == token)
		return -1;

	if (strcasecmp(token, "ODP_PMR_ETHTYPE_0") == 0) {
		*term = ODP_PMR_ETHTYPE_0;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_VLAN_ID_0") == 0) {
		*term = ODP_PMR_VLAN_ID_0;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_SIP_ADDR") == 0) {
		*term = ODP_PMR_SIP_ADDR;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_CUSTOM_FRAME") == 0) {
		*term = ODP_PMR_CUSTOM_FRAME;
		return 0;
	}

	return -1;
}

static int parse_pmr_policy(appl_args_t *appl_args, char *argv[], char *optarg)
{
	int policy_count;
	char *token, *cos0, *cos1;
	size_t len;
	odp_cls_pmr_term_t term;
	global_statistics *stats;
	char *pmr_str;
	uint32_t offset;
	uint32_t ip_addr;
	unsigned long int value;

	policy_count = appl_args->policy_count;
	stats = appl_args->stats;

	/* last array index is needed for default queue */
	if (policy_count >= MAX_PMR_COUNT - 1) {
		ODPH_ERR("Maximum allowed PMR reached\n");
		return -1;
	}

	len = strlen(optarg);
	len++;
	pmr_str = malloc(len);
	strcpy(pmr_str, optarg);

	/* PMR TERM */
	/* <term>:<xxx>:<yyy>:<src_cos>:<dst_cos> */
	token = strtok(pmr_str, ":");
	if (convert_str_to_pmr_enum(token, &term)) {
		ODPH_ERR("Invalid ODP_PMR_TERM string\n");
		exit(EXIT_FAILURE);
	}
	stats[policy_count].rule.term = term;
	stats[policy_count].rule.offset = 0;

	/* PMR value */
	switch (term) {
	case ODP_PMR_ETHTYPE_0:
		/* :<type>:<mask> */
		/* Fall through */
	case ODP_PMR_VLAN_ID_0:
		/* :<vlan_id>:<mask> */
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].value, token,
			DISPLAY_STRING_LEN - 1);
		value = strtoul(token, NULL, 0);
		stats[policy_count].rule.val = value;

		token = strtok(NULL, ":");
		strncpy(stats[policy_count].mask, token,
			DISPLAY_STRING_LEN - 1);
		parse_mask(token, &stats[policy_count].rule.mask);
		stats[policy_count].rule.val_sz = 2;
	break;
	case ODP_PMR_SIP_ADDR:
		/* :<IP addr>:<mask> */
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].value, token,
			DISPLAY_STRING_LEN - 1);

		if (odph_ipv4_addr_parse(&ip_addr, token)) {
			ODPH_ERR("Bad IP address\n");
			exit(EXIT_FAILURE);
		}

		stats[policy_count].rule.val = ip_addr;

		token = strtok(NULL, ":");
		strncpy(stats[policy_count].mask, token,
			DISPLAY_STRING_LEN - 1);
		parse_mask(token, &stats[policy_count].rule.mask);
		stats[policy_count].rule.val_sz = 4;
	break;
	case ODP_PMR_CUSTOM_FRAME:
		/* :<offset>:<value>:<mask> */
		token = strtok(NULL, ":");
		errno = 0;
		offset = strtoul(token, NULL, 0);
		if (errno)
			return -1;

		token = strtok(NULL, ":");
		strncpy(stats[policy_count].value, token,
			DISPLAY_STRING_LEN - 1);
		parse_value(token, &stats[policy_count].rule.val,
			    &stats[policy_count].rule.val_sz);
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].mask, token,
			DISPLAY_STRING_LEN - 1);
		parse_mask(token, &stats[policy_count].rule.mask);
		stats[policy_count].rule.offset = offset;
	break;
	default:
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Optional source CoS name and name of this CoS
	 * :<src_cos>:<cos> */
	cos0 = strtok(NULL, ":");
	cos1 = strtok(NULL, ":");
	if (cos0 == NULL)
		return -1;

	if (cos1) {
		stats[policy_count].has_src_cos = 1;
		strncpy(stats[policy_count].src_cos_name, cos0,
			ODP_COS_NAME_LEN - 1);
		strncpy(stats[policy_count].cos_name, cos1,
			ODP_COS_NAME_LEN - 1);
	} else {
		strncpy(stats[policy_count].cos_name, cos0,
			ODP_COS_NAME_LEN - 1);
	}

	appl_args->policy_count++;
	free(pmr_str);
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	size_t len;
	int i;
	int interface = 0;
	int policy = 0;

	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},
		{"policy", required_argument, NULL, 'p'},
		{"mode", required_argument, NULL, 'm'},
		{"time", required_argument, NULL, 't'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:i:p:m:t:vh";

	appl_args->cpu_count = 1; /* Use one worker by default */
	appl_args->verbose = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts,
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'p':
			if (0 > parse_pmr_policy(appl_args, argv, optarg))
				continue;
			policy = 1;
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_name = malloc(len);
			if (appl_args->if_name == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->if_name, optarg);
			interface = 1;
			break;
		case 'm':
			i = atoi(optarg);
			if (i == 0)
				appl_args->appl_mode = APPL_MODE_DROP;
			else
				appl_args->appl_mode = APPL_MODE_REPLY;
			break;
		case 'v':
			appl_args->verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (!interface ||  !policy) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (appl_args->if_name == NULL) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
			"-----------------\n"
			"Using IF:%s      ",
			progname, appl_args->if_name);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
			"OpenDataPlane Classifier example.\n"
			"Usage: %s OPTIONS\n"
			"  E.g. %s -i eth1 -m 0 -p \"ODP_PMR_SIP_ADDR:10.10.10.5:FFFFFFFF:queue1\" \\\n"
			"\t\t\t-p \"ODP_PMR_SIP_ADDR:10.10.10.7:000000FF:queue2\" \\\n"
			"\t\t\t-p \"ODP_PMR_SIP_ADDR:10.5.5.10:FFFFFF00:queue3\"\n"
			"\n"
			"For the above example configuration the following will be the packet distribution\n"
			"queue1\t\tPackets with source ip address 10.10.10.5\n"
			"queue2\t\tPackets with source ip address whose last 8 bits match 7\n"
			"queue3\t\tPackets with source ip address in the subnet 10.5.5.0\n"
			"\n"
			"Mandatory OPTIONS:\n"
			"  -i, --interface Eth interface\n"
			"  -p, --policy [<odp_cls_pmr_term_t>|<offset>]:<value>:<mask bits>:<queue name>\n"
			"\n"
			"<odp_cls_pmr_term_t>	Packet Matching Rule defined with odp_cls_pmr_term_t "
			"for the policy\n"
			"<offset>		Absolute offset in bytes from frame start to define a "
			"ODP_PMR_CUSTOM_FRAME Packet Matching Rule for the policy\n"
			"\n"
			"<value>		PMR value to be matched.\n"
			"\n"
			"<mask  bits>		PMR mask bits to be applied on the PMR term value\n"
			"\n"
			"Optional OPTIONS\n"
			"  -c, --count <number> CPU count, 0=all available, default=1\n"
			"\n"
			"  -m, --mode		0: Packet Drop mode. Received packets will be dropped\n"
			"			!0: Packet ICMP mode. Received packets will be sent back\n"
			"                       default: Packet Drop mode\n"
			"\n"
			" -t, --timeout		!0: Time for which the classifier will be run in seconds\n"
			"			0: Runs in infinite loop\n"
			"			default: Runs in infinite loop\n"
			"\n"
			"  -h, --help		Display help and exit.\n"
			"\n", NO_PATH(progname), NO_PATH(progname)
	      );
}
