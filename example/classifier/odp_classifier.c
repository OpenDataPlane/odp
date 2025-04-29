/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2022 Nokia
 * Copyright (c) 2020 Marvell
 */

/**
 * @example odp_classifier.c
 *
 * Classifier API example application
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
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

/** @def MAX_PKT_BURST
 * @brief Maximum packet burst size
 */
#define MAX_PKT_BURST 64

/** @def DEF_PKT_BURST
 * @brief Default packet burst size
 */
#define DEF_PKT_BURST 32

/** @def SHM_PKT_POOL_SIZE
 * @brief Packet pool size (number of packets)
 */
#define SHM_PKT_POOL_SIZE 10000

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PMR_COUNT
 * @brief Maximum number of Classification Policy
 */
#define MAX_PMR_COUNT 32

/** @def DISPLAY_STRING_LEN
 * @brief Length of string used to display term value
 */
#define DISPLAY_STRING_LEN	32

/** Maximum PMR value size */
#define MAX_VAL_SIZE    16

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
		uint8_t value_be[MAX_VAL_SIZE]; /**< value in big endian */
		uint8_t mask_be[MAX_VAL_SIZE];  /**< mask in big endian */
		uint32_t val_sz;	/**< size of the pmr term */
		uint32_t offset;	/**< pmr term offset */
	} rule;
	char value[DISPLAY_STRING_LEN];	/**< Display string for value */
	char mask[DISPLAY_STRING_LEN];	/**< Display string for mask */
	int has_src_cos;

} global_statistics;

typedef struct {
	char cos_name[ODP_COS_NAME_LEN];
	uint64_t count;
} ci_pass_counters;

typedef struct {
	odp_pktout_queue_t pktout[MAX_WORKERS];
	int num_pktout;
	global_statistics stats[MAX_PMR_COUNT];
	ci_pass_counters ci_pass_rules[MAX_PMR_COUNT];
	int policy_count;	/**< global policy count */
	int num_ci_pass_rules;	/**< ci pass count */
	int appl_mode;		/**< application mode */
	odp_atomic_u64_t total_packets;	/**< total received packets */
	unsigned int cpu_count; /**< Number of CPUs to use */
	uint32_t time;		/**< Number of seconds to run */
	char *if_name;		/**< pointer to interface names */
	int shutdown;		/**< Shutdown threads if !0 */
	int shutdown_sig;
	int verbose;
	int promisc_mode;	/**< Promiscuous mode enabled */
	int classifier_enable;
	int parse_layer;
	int cos_pools;
	int pool_size;
	int burst_size;
} appl_args_t;

enum packet_mode {
	APPL_MODE_DROP,		/**< Packet is dropped */
	APPL_MODE_REPLY		/**< Packet is sent back */
};

static appl_args_t *appl_args_gbl;

static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(void);

static inline int check_ci_pass_count(appl_args_t *args)
{
	int i, j;
	uint64_t count;

	if (args->num_ci_pass_rules == 0)
		return 0;

	for (i = 0; i < args->num_ci_pass_rules; i++) {
		for (j = 0; j < args->policy_count; j++) {
			if (!strcmp(args->stats[j].cos_name,
				    args->ci_pass_rules[i].cos_name)) {
				count = odp_atomic_load_u64(&args->stats[i].queue_pkt_count);
				if (args->ci_pass_rules[i].count > count) {
					ODPH_ERR("Error: Cos = %s, expected packets = %" PRIu64 ","
						 "received packet = %" PRIu64 "\n",
						 args->stats[j].cos_name,
						 args->ci_pass_rules[i].count, count);
					return -1;
				}
				break;
			}
		}
		if (j == args->policy_count) {
			ODPH_ERR("Error: invalid Cos:%s specified for CI pass count\n",
				 args->ci_pass_rules[i].cos_name);
			return -1;
		}
	}
	return 0;
}

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
	printf("%-6s %-6s", "Total", "Mpps");
	printf("\n");
	for (i = 0; i < args->policy_count; i++)
		printf("%-6s %-6s|", "queue", "pool");
	printf("\n");

	timeout = args->time;

	/* Incase if default value is given for timeout
	run the loop infinitely */
	if (timeout == 0)
		infinite = 1;

	uint64_t total_packets, last_total_packets = 0;
	odp_time_t start = odp_time_local(), end;
	float mpps;

	for (; timeout > 0 || infinite; timeout--) {
		sleep(1);
		for (i = 0; i < args->policy_count; i++) {
			printf("%-6" PRIu64 " ",
			       odp_atomic_load_u64(&args->stats[i]
						   .queue_pkt_count));
			printf("%-6" PRIu64 "|",
			       odp_atomic_load_u64(&args->stats[i]
						   .pool_pkt_count));
		}

		end = odp_time_local();
		total_packets = odp_atomic_load_u64(&args->total_packets);
		mpps = (total_packets - last_total_packets) /
		       (odp_time_diff_ns(end, start) / 1000.0);
		printf("%-6" PRIu64 " %-6.3f\n", total_packets, mpps);
		last_total_packets = total_packets;
		start = end;

		if (args->shutdown_sig)
			break;
	}

	printf("\n");
}

static int parse_custom(const char *str, uint8_t *buf_be, int max_size)
{
	int i, len;

	/* hex string without 0x prefix */
	len = strlen(str);
	if (len > 2 * max_size)
		return -1;

	for (i = 0; i < len; i += 2)
		if (sscanf(&str[i], "%2" SCNx8, &buf_be[i / 2]) != 1)
			return -1;

	return len / 2;
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
	odp_pktio_capability_t capa;
	odp_pktio_config_t cfg;
	odp_pktout_queue_param_t pktout_queue_param;
	int num_tx;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("pktio create failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	if (odp_pktio_capability(pktio, &capa)) {
		ODPH_ERR("pktio capability failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.classifier_enable = appl_args_gbl->classifier_enable;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		ODPH_ERR("pktin queue config failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	num_tx = appl_args_gbl->cpu_count;

	if (num_tx > (int)capa.max_output_queues) {
		printf("Sharing %i output queues between %i workers\n",
		       capa.max_output_queues, num_tx);
		num_tx = capa.max_output_queues;
	}

	appl_args_gbl->num_pktout = num_tx;

	odp_pktout_queue_param_init(&pktout_queue_param);
	pktout_queue_param.num_queues = num_tx;

	if (odp_pktout_queue_config(pktio, &pktout_queue_param)) {
		ODPH_ERR("pktout queue config failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	if (odp_pktout_queue(pktio, appl_args_gbl->pktout, num_tx) != num_tx) {
		ODPH_ERR("Pktout queue query failed: %s\n", dev);
		exit(EXIT_FAILURE);
	}

	if (appl_args_gbl->promisc_mode && odp_pktio_promisc_mode(pktio) != 1) {
		if (!capa.set_op.op.promisc_mode) {
			ODPH_ERR("enabling promisc mode not supported %s\n", dev);
			exit(EXIT_FAILURE);
		}

		if (odp_pktio_promisc_mode_set(pktio, true)) {
			ODPH_ERR("failed to enable promisc mode for %s\n", dev);
			exit(EXIT_FAILURE);
		}
	}

	printf("created pktio:%" PRIu64 ", dev:%s", odp_pktio_to_u64(pktio), dev);

	odph_ethaddr_t mac;

	if (odp_pktio_mac_addr(pktio, &mac, sizeof(mac)) == sizeof(mac)) {
		printf(", mac");
		for (int c = 0; c < (int)sizeof(mac); c++)
			printf(":%02x", mac.addr[c]);
	}

	printf("\n");

	odp_pktio_config_init(&cfg);
	cfg.parser.layer = appl_args_gbl->parse_layer;
	if (odp_pktio_config(pktio, &cfg)) {
		ODPH_ERR("failed to configure pktio %s\n", dev);
		exit(EXIT_FAILURE);
	}

	return pktio;
}

/**
 * Worker threads to receive the packet
 *
 */
static int pktio_receive_thread(void *arg)
{
	int thr;
	odp_packet_t pkt[MAX_PKT_BURST];
	odp_pool_t pool;
	odp_event_t ev[MAX_PKT_BURST];
	odp_queue_t queue;
	int i, j, num, dropped, sent;
	global_statistics *stats;
	unsigned long err_cnt = 0;
	thr = odp_thread_id();
	appl_args_t *appl = (appl_args_t *)arg;
	uint64_t wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	odp_pktout_queue_t pktout = appl_args_gbl->pktout[thr % appl_args_gbl->num_pktout];

	/* Loop packets */
	for (;;) {
		if (appl->shutdown)
			break;

		/* Use schedule to get buf from any input queue */
		num = odp_schedule_multi(&queue, wait_time, ev, appl_args_gbl->burst_size);

		/* Loop back to receive packets incase of invalid event */
		if (odp_unlikely(!num))
			continue;

		odp_packet_from_event_multi(pkt, ev, num);

		if (odp_unlikely(appl->verbose)) {
			for (j = 0; j < num; j++) {
				odp_queue_info_t info;
				uint32_t len = odp_packet_len(pkt[j]);

				if (odp_queue_info(queue, &info) == 0)
					printf("Queue: %s\n", info.name);

				if (len > 96)
					len = 96;

				odp_packet_print_data(pkt[j], 0, len);
			}
		}

		/* Total packets received */
		odp_atomic_add_u64(&appl->total_packets, num);

		/* Drop packets with errors */
		dropped = drop_err_pkts(pkt, num);
		if (odp_unlikely(dropped)) {
			num -= dropped;
			err_cnt += dropped;
			ODPH_ERR("Drop frame - err_cnt:%lu\n", err_cnt);
		}

		for (j = 0; j < num; j++) {
			pool = odp_packet_pool(pkt[j]);

			for (i = 0; i <  MAX_PMR_COUNT; i++) {
				stats = &appl->stats[i];
				if (queue == stats->queue)
					odp_atomic_inc_u64(&stats->queue_pkt_count);
				if (pool == stats->pool)
					odp_atomic_inc_u64(&stats->pool_pkt_count);
			}
		}

		if (appl->appl_mode == APPL_MODE_DROP) {
			odp_packet_free_multi(pkt, num);
			continue;
		}

		/* Swap Eth MACs and possibly IP-addrs before sending back */
		swap_pkt_addrs(pkt, num);

		sent = odp_pktout_send(pktout, pkt, num);
		sent = sent < 0 ? 0 : sent;

		if (sent != num) {
			ODPH_ERR("  [%i] Packet send failed\n", thr);
			odp_packet_free_multi(pkt + sent, num - sent);
		}
	}

	return 0;
}

static odp_pool_t pool_create(const char *name)
{
	static odp_pool_t pool = ODP_POOL_INVALID;
	odp_pool_param_t pool_params;

	if (!appl_args_gbl->cos_pools && pool != ODP_POOL_INVALID)
		return pool;

	odp_pool_param_init(&pool_params);
	pool_params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.len = SHM_PKT_POOL_BUF_SIZE;
	pool_params.pkt.num = appl_args_gbl->pool_size;
	pool_params.type = ODP_POOL_PACKET;
	pool = odp_pool_create(name, &pool_params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: failed to create pool %s\n", name);
		exit(EXIT_FAILURE);
	}

	return pool;
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
	odp_cls_cos_param_t cls_param;
	global_statistics *stats = args->stats;


	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	queue_default = odp_queue_create(queue_name, &qparam);
	if (queue_default == ODP_QUEUE_INVALID) {
		ODPH_ERR("Error: default queue create failed\n");
		exit(EXIT_FAILURE);
	}

	pool_default = pool_create(pool_name);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_default;
	cls_param.queue = queue_default;

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
	if (appl_args_gbl->cos_pools)
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
	odp_cls_cos_param_t cls_param;
	int i;
	global_statistics *stats;
	odp_queue_param_t qparam;

	for (i = 0; i < args->policy_count - 1; i++) {
		stats = &args->stats[i];

		odp_queue_param_init(&qparam);
		qparam.type       = ODP_QUEUE_TYPE_SCHED;
		qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;

		queue_name = args->stats[i].cos_name;
		stats->queue = odp_queue_create(queue_name, &qparam);
		if (ODP_QUEUE_INVALID == stats->queue) {
			ODPH_ERR("odp_queue_create failed\n");
			exit(EXIT_FAILURE);
		}

		snprintf(pool_name, sizeof(pool_name), "%sPool%d",
			 args->stats[i].cos_name, i);

		snprintf(cos_name, sizeof(cos_name), "CoS%s",
			 stats->cos_name);
		odp_cls_cos_param_init(&cls_param);
		cls_param.pool = pool_create(pool_name);
		if (appl_args_gbl->cos_pools)
			stats->pool = cls_param.pool;
		cls_param.queue = stats->queue;

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
		pmr_param.match.value = stats->rule.value_be;
		pmr_param.match.mask  = stats->rule.mask_be;
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
	if (parse_args(argc, argv, args))
		goto args_error;

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
	pool = pool_create("packet_pool");

	/* Configure scheduler */
	odp_schedule_config(NULL);

	/* odp_pool_print(pool); */
	odp_atomic_init_u64(&args->total_packets, 0);

	/* create pktio per interface */
	pktio = create_pktio(args->if_name, pool);

	/* configure default Cos */
	default_cos = configure_default_cos(pktio, args);

	configure_cos(default_cos, args);

	printf("\n");
	odp_pool_print_all();
	odp_cls_print_all();

	if (odp_pktio_start(pktio)) {
		ODPH_ERR("Error: unable to start pktio\n");
		exit(EXIT_FAILURE);
	}

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	odph_thread_common_param_init(&thr_common);
	odph_thread_param_init(&thr_param);

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

	if (check_ci_pass_count(args)) {
		ODPH_ERR("Error: Packet count verification failed\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < args->policy_count; i++) {
		if ((i !=  args->policy_count - 1) &&
		    odp_cls_pmr_destroy(args->stats[i].pmr))
			ODPH_ERR("err: odp_cls_pmr_destroy for %d\n", i);
		if (odp_cos_destroy(args->stats[i].cos))
			ODPH_ERR("err: odp_cos_destroy for %d\n", i);
		if (odp_queue_destroy(args->stats[i].queue))
			ODPH_ERR("err: odp_queue_destroy for %d\n", i);
		if (args->cos_pools && odp_pool_destroy(args->stats[i].pool))
			ODPH_ERR("err: odp_pool_destroy for %d\n", i);
	}

	if (odp_pktio_close(pktio))
		ODPH_ERR("err: close pktio error\n");
	if (odp_pool_destroy(pool))
		ODPH_ERR("err: odp_pool_destroy error\n");

	free(args->if_name);

args_error:
	odp_shm_free(shm);

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
 * @return Number of packets dropped
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned i, j;
	int dropped = 0;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			dropped++;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return dropped;
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
	} else if (strcasecmp(token, "ODP_PMR_ETHTYPE_X") == 0) {
		*term = ODP_PMR_ETHTYPE_X;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_VLAN_ID_0") == 0) {
		*term = ODP_PMR_VLAN_ID_0;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_VLAN_ID_X") == 0) {
		*term = ODP_PMR_VLAN_ID_X;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_UDP_DPORT") == 0) {
		*term = ODP_PMR_UDP_DPORT;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_TCP_DPORT") == 0) {
		*term = ODP_PMR_TCP_DPORT;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_UDP_SPORT") == 0) {
		*term = ODP_PMR_UDP_SPORT;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_TCP_SPORT") == 0) {
		*term = ODP_PMR_TCP_SPORT;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_DIP_ADDR") == 0) {
		*term = ODP_PMR_DIP_ADDR;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_SIP_ADDR") == 0) {
		*term = ODP_PMR_SIP_ADDR;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_DMAC") == 0) {
		*term = ODP_PMR_DMAC;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_CUSTOM_FRAME") == 0) {
		*term = ODP_PMR_CUSTOM_FRAME;
		return 0;
	} else if (strcasecmp(token, "ODP_PMR_CUSTOM_L3") == 0) {
		*term = ODP_PMR_CUSTOM_L3;
		return 0;
	}

	return -1;
}

static int parse_pmr_policy(appl_args_t *appl_args, char *optarg)
{
	int policy_count;
	char *token, *cos0, *cos1, *cur_char;
	size_t len;
	odp_cls_pmr_term_t term;
	global_statistics *stats;
	odph_ethaddr_t mac;
	char *pmr_str;
	uint32_t offset, ip_addr, u32;
	unsigned long int value, mask;
	uint16_t u16;
	int val_sz, mask_sz;

	policy_count = appl_args->policy_count;
	stats = appl_args->stats;

	/* last array index is needed for default queue */
	if (policy_count >= MAX_PMR_COUNT - 1) {
		ODPH_ERR("Too many policies. Max count is %i.\n",
			 MAX_PMR_COUNT - 1);
		return -1;
	}

	len = strlen(optarg);
	len++;
	pmr_str = malloc(len);
	if (pmr_str == NULL) {
		ODPH_ERR("Memory allocation failed\n");
		return -1;
	}
	strcpy(pmr_str, optarg);

	/* PMR TERM */
	/* <term>:<xxx>:<yyy>:<src_cos>:<dst_cos> */
	token = strtok(pmr_str, ":");
	if (convert_str_to_pmr_enum(token, &term)) {
		ODPH_ERR("Invalid ODP_PMR_TERM string\n");
		goto error;
	}
	stats[policy_count].rule.term = term;
	stats[policy_count].rule.offset = 0;

	/* PMR value */
	switch (term) {
	case ODP_PMR_ETHTYPE_0:
		/* Fall through */
	case ODP_PMR_ETHTYPE_X:
		/* Fall through */
		/* :<type>:<mask> */
	case ODP_PMR_VLAN_ID_0:
		/* Fall through */
	case ODP_PMR_VLAN_ID_X:
		/* Fall through */
		/* :<vlan_id>:<mask> */
	case ODP_PMR_UDP_DPORT:
		/* Fall through */
	case ODP_PMR_TCP_DPORT:
		/* Fall through */
	case ODP_PMR_UDP_SPORT:
		/* Fall through */
	case ODP_PMR_TCP_SPORT:
		/* :<port>:<mask> */
		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].value, token,
			    DISPLAY_STRING_LEN);
		value = strtoul(token, NULL, 0);
		u16 = value;
		u16 = odp_cpu_to_be_16(u16);
		memcpy(stats[policy_count].rule.value_be, &u16, sizeof(u16));

		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].mask, token,
			    DISPLAY_STRING_LEN);
		mask = strtoul(token, NULL, 0);
		u16 = mask;
		u16 = odp_cpu_to_be_16(u16);
		memcpy(stats[policy_count].rule.mask_be, &u16, sizeof(u16));

		stats[policy_count].rule.val_sz = 2;
	break;
	case ODP_PMR_DIP_ADDR:
		/* Fall through */
	case ODP_PMR_SIP_ADDR:
		/* :<IP addr>:<mask> */
		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].value, token,
			    DISPLAY_STRING_LEN);

		if (odph_ipv4_addr_parse(&ip_addr, token)) {
			ODPH_ERR("Bad IP address\n");
			goto error;
		}

		u32 = odp_cpu_to_be_32(ip_addr);
		memcpy(stats[policy_count].rule.value_be, &u32, sizeof(u32));

		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].mask, token,
			    DISPLAY_STRING_LEN);
		mask = strtoul(token, NULL, 0);
		u32 = mask;
		u32 = odp_cpu_to_be_32(u32);
		memcpy(stats[policy_count].rule.mask_be, &u32, sizeof(u32));

		stats[policy_count].rule.val_sz = 4;
	break;
	case ODP_PMR_DMAC:
		/* :<MAC addr>:<mask> */
		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].value, token,
			    DISPLAY_STRING_LEN);

		/* Replace hyphens in the MAC string with colons to be compatible with
		 * odph_eth_addr_parse(). */
		cur_char = token;
		while ((cur_char = strchr(cur_char, '-')) != NULL)
			*cur_char++ = ':';

		if (odph_eth_addr_parse(&mac, token)) {
			ODPH_ERR("Invalid MAC address. Use format 11-22-33-44-55-66.\n");
			goto error;
		}

		memcpy(stats[policy_count].rule.value_be, mac.addr, ODPH_ETHADDR_LEN);
		stats[policy_count].rule.val_sz = 6;

		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].mask, token, DISPLAY_STRING_LEN);
		mask_sz = parse_custom(token, stats[policy_count].rule.mask_be, ODPH_ETHADDR_LEN);
		if (mask_sz != ODPH_ETHADDR_LEN) {
			ODPH_ERR("Invalid mask. Provide mask without 0x prefix.\n");
			goto error;
		}
	break;
	case ODP_PMR_CUSTOM_FRAME:
		/* Fall through */
	case ODP_PMR_CUSTOM_L3:
		/* :<offset>:<value>:<mask> */
		token = strtok(NULL, ":");
		errno = 0;
		offset = strtoul(token, NULL, 0);
		stats[policy_count].rule.offset = offset;
		if (errno)
			goto error;

		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].value, token,
			    DISPLAY_STRING_LEN);
		val_sz = parse_custom(token,
				      stats[policy_count].rule.value_be,
				      MAX_VAL_SIZE);
		stats[policy_count].rule.val_sz = val_sz;
		if (val_sz <= 0)
			goto error;

		token = strtok(NULL, ":");
		odph_strcpy(stats[policy_count].mask, token,
			    DISPLAY_STRING_LEN);
		mask_sz = parse_custom(token,
				       stats[policy_count].rule.mask_be,
				       MAX_VAL_SIZE);
		if (mask_sz != val_sz)
			goto error;
	break;
	default:
		goto error;
	}

	/* Optional source CoS name and name of this CoS
	 * :<src_cos>:<cos> */
	cos0 = strtok(NULL, ":");
	cos1 = strtok(NULL, ":");
	if (cos0 == NULL)
		goto error;

	if (cos1) {
		stats[policy_count].has_src_cos = 1;
		odph_strcpy(stats[policy_count].src_cos_name, cos0,
			    ODP_COS_NAME_LEN);
		odph_strcpy(stats[policy_count].cos_name, cos1,
			    ODP_COS_NAME_LEN);
	} else {
		odph_strcpy(stats[policy_count].cos_name, cos0,
			    ODP_COS_NAME_LEN);
	}

	appl_args->policy_count++;
	free(pmr_str);
	return 0;

error:
	free(pmr_str);
	return -1;
}

static int parse_policy_ci_pass_count(appl_args_t *appl_args, char *optarg)
{
	int num_ci_pass_rules;
	char *token, *value;
	size_t len;
	ci_pass_counters *ci_pass_rules;
	char *count_str;

	num_ci_pass_rules = appl_args->num_ci_pass_rules;
	ci_pass_rules = appl_args->ci_pass_rules;

	/* last array index is needed for default queue */
	if (num_ci_pass_rules >= MAX_PMR_COUNT) {
		ODPH_ERR("Too many ci pass counters. Max count is %i.\n",
			 MAX_PMR_COUNT);
		return -1;
	}

	len = strlen(optarg);
	len++;
	count_str = malloc(len);
	if (count_str == NULL) {
		ODPH_ERR("Memory allocation failed\n");
		return -1;
	}
	strcpy(count_str, optarg);

	token = strtok(count_str, ":");
	value = strtok(NULL, ":");
	if (!token || !value) {
		free(count_str);
		return -1;
	}
	odph_strcpy(ci_pass_rules[num_ci_pass_rules].cos_name, token, ODP_COS_NAME_LEN);
	ci_pass_rules[num_ci_pass_rules].count = atoll(value);
	appl_args->num_ci_pass_rules++;
	free(count_str);
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	size_t len;
	int i;
	int interface = 0;
	int ret = 0;

	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},
		{"policy", required_argument, NULL, 'p'},
		{"mode", required_argument, NULL, 'm'},
		{"time", required_argument, NULL, 't'},
		{"ci_pass", required_argument, NULL, 'C'},
		{"promisc_mode", no_argument, NULL, 'P'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{"enable", required_argument, NULL, 'e'},
		{"layer", required_argument, NULL, 'l'},
		{"dedicated", required_argument, NULL, 'd'},
		{"size", required_argument, NULL, 's'},
		{"burst", required_argument, NULL, 'b'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:i:p:m:t:C:Pvhe:l:d:s:b:";

	appl_args->cpu_count = 1; /* Use one worker by default */
	appl_args->verbose = 0;
	appl_args->promisc_mode = 0;
	appl_args->classifier_enable = 1;
	appl_args->parse_layer = ODP_PROTO_LAYER_ALL;
	appl_args->cos_pools = 1;
	appl_args->pool_size = SHM_PKT_POOL_SIZE;
	appl_args->burst_size = DEF_PKT_BURST;

	while (ret == 0) {
		opt = getopt_long(argc, argv, shortopts,
				  longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'p':
			if (parse_pmr_policy(appl_args, optarg)) {
				ret = -1;
				break;
			}
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				ret = -1;
				break;
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_name = malloc(len);
			if (appl_args->if_name == NULL) {
				ret = -1;
				break;
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
		case 'C':
			if (parse_policy_ci_pass_count(appl_args, optarg)) {
				ret = -1;
				break;
			}
			break;
		case 'P':
			appl_args->promisc_mode = 1;
			break;
		case 'v':
			appl_args->verbose = 1;
			break;
		case 'h':
			ret = -1;
			break;
		case 'e':
			appl_args->classifier_enable = atoi(optarg);
			break;
		case 'l':
			appl_args->parse_layer = atoi(optarg);
			break;
		case 'd':
			appl_args->cos_pools = atoi(optarg);
			break;
		case 's':
			appl_args->pool_size = atoi(optarg);
			break;
		case 'b':
			appl_args->burst_size = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (!interface)
		ret = -1;

	if (appl_args->if_name == NULL)
		ret = -1;

	if (ret) {
		usage();
		free(appl_args->if_name);
	}

	/* reset optind from the getopt lib */
	optind = 1;

	return ret;
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
			"-----------------\n"
			"Using IF:        %s\n",
			progname, appl_args->if_name);
	printf("Promisc mode:    %s\n", appl_args->promisc_mode ? "enabled" : "disabled");
	printf("\n\n");
	fflush(NULL);
}

/**
 * Print usage information
 */
static void usage(void)
{
	printf("\n"
		"ODP Classifier example.\n"
		"Usage: odp_classifier OPTIONS\n"
		"  E.g. odp_classifier -i eth1 -m 0 -p \"ODP_PMR_SIP_ADDR:10.10.10.0:0xFFFFFF00:queue1\" \\\n"
		"                                   -p \"ODP_PMR_SIP_ADDR:10.10.10.10:0xFFFFFFFF:queue1:queue2\"\n"
		"\n"
		"The above example would classify:\n"
		"  1) Packets from source IP address 10.10.10.0/24 to queue1, except ...\n"
		"  2) Packets from source IP address 10.10.10.10 to queue2\n"
		"  3) All other packets to DefaultCos\n"
		"\n"
		"Mandatory OPTIONS:\n"
		"  -i, --interface <interface name>\n"
		"\n"
		"Optional OPTIONS\n"
		"  -p, --policy <PMR term>:<offset>:<value>:<mask>:<src queue>:<dst queue>\n"
		"\n"
		"    <PMR term>             PMR term name defined in odp_cls_pmr_term_t\n"
		"    <offset>               If term is ODP_PMR_CUSTOM_FRAME or _CUSTOM_L3, offset in bytes is used\n"
		"    <value>                PMR value to be matched\n"
		"    <mask>                 PMR mask bits to be applied on the PMR value.\n"
		"                           CUSTOM PMR terms accept plain hex string, other PMR terms require\n"
		"                           hex string with '0x' prefix.\n"
		"    <src queue>            Optional name of the source queue (CoS). The default CoS is used when\n"
		"                           this is not defined.\n"
		"    <dst queue>            Name of the destination queue (CoS).\n"
		"\n"
		"  -c, --count <num>        CPU count, 0=all available, default=1\n"
		"\n"
		"  -m, --mode <mode>        0: Packet Drop mode. Received packets will be dropped\n"
		"                           !0: Echo mode. Received packets will be sent back\n"
		"                           default: Packet Drop mode\n"
		"\n"
		"  -t, --time <sec>         !0: Time for which the classifier will be run in seconds\n"
		"                           0: Runs in infinite loop\n"
		"                           default: Runs in infinite loop\n"
		"\n"
		"  -e, --enable <enable>    0: Classifier is disabled\n"
		"                           1: Classifier is enabled\n"
		"                           default: Classifier is enabled\n"
		"\n"
		"  -l, --layer <layer>      Parse packets up to and including this layer. See odp_proto_layer_t\n"
		"                           default: ODP_PROTO_LAYER_ALL\n"
		"\n"
		"  -d, --dedicated <enable> 0: One pool for pktio and all CoSes\n"
		"                           1: Dedicated pools for pktio and each CoS\n"
		"                           default: Dedicated pools\n"
		"\n"
		"  -s, --size <num>         Number of packets in each packet pool\n"
		"                           default: %d\n"
		"\n"
		"  -b, --burst <num>        Packet burst size\n"
		"                           default: %d\n"
		"\n"
		"  -C, --ci_pass <dst queue:count>\n"
		"                           Minimum acceptable packet count for a CoS destination queue.\n"
		"                           If the received packet count is smaller than this value,\n"
		"                           the application will exit with an error.\n"
		"                            E.g: -C \"queue1:100\" -C \"queue2:200\" -C \"DefaultQueue:100\"\n"
		"  -P, --promisc_mode       Enable promiscuous mode.\n"
		"  -v, --verbose            Verbose output.\n"
		"  -h, --help               Display help and exit.\n"
		"\n", SHM_PKT_POOL_SIZE, DEF_PKT_BURST);
}
