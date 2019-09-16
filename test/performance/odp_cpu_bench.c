/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Queues are divided into groups and tests packets are passed only between
 * queues which belong to the same group. */
#define MAX_GROUPS       64
#define QUEUES_PER_GROUP 4
#define PKTS_PER_QUEUE   256

#define MAX_EVENT_BURST  32
#define CRC_INIT_VAL     123456789
#define PASS_PACKETS     10000

/* Default number of entries in the test lookup table */
#define DEF_LOOKUP_TBL_SIZE (1024 * 1024)

#define MAX_WORKERS      (ODP_THREAD_COUNT_MAX - 1)
ODP_STATIC_ASSERT(MAX_WORKERS <= MAX_GROUPS * QUEUES_PER_GROUP,
		  "Not enough queues for all workers");

/* Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/* Test dummy lookup table entry */
typedef struct {
	uint64_t idx;
	uint32_t val0;
	uint32_t val1;
} lookup_entry_t;

/* Test packet */
typedef struct {
	uint32_t seq;
	uint32_t crc;
	uint16_t group;
} test_hdr_t;

/* Parsed application arguments */
typedef struct {
	uint64_t lookup_tbl_size; /* Lookup table size */
	int accuracy; /* Number of seconds between stats prints */
	unsigned int cpu_count; /* CPU count */
	int time; /* Time in seconds to run */
} appl_args_t;

/* Statistics */
typedef union ODP_ALIGNED_CACHE {
	struct {
		/* Number of processed packets */
		uint64_t pkts;
		/* Number of dropped packets */
		uint64_t dropped_pkts;
		/* Time spent processing packets */
		uint64_t nsec;
		/* Cycles spent processing packets */
		uint64_t cycles;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/* Thread specific data */
typedef struct thread_args_t {
	stats_t stats;
	uint16_t idx;
} thread_args_t;

/* Grouping of all global data */
typedef struct {
	/* Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/* Barriers to synchronize main and workers */
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	/* Application (parsed) arguments */
	appl_args_t appl;
	/* Test queues */
	odp_queue_t queue[MAX_GROUPS][QUEUES_PER_GROUP];
	/* Test lookup table */
	lookup_entry_t *lookup_tbl;
	/* Break workers loop if set to 1 */
	int exit_threads;
} args_t;

/* Global pointer to args */
static args_t *gbl_args;

static const uint8_t test_udp_packet[] = {
	0x00, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x08, 0x00, 0x45, 0x00,
	0x02, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
	0xF7, 0x7C, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x04, 0xD2, 0x1A, 0x82, 0x02, 0x08,
	0x24, 0x1E, 0xC9, 0x56, 0xB4, 0xD6, 0x4B, 0x64,
	0xB3, 0x01, 0xA1, 0x97, 0x4D, 0xD1, 0xA4, 0x76,
	0xF5, 0x7B, 0x27, 0x22, 0x6C, 0xA9, 0xED, 0x29,
	0x6E, 0x02, 0x80, 0xF7, 0xC4, 0x2D, 0x2A, 0x96,
	0x2D, 0xF6, 0x02, 0x8E, 0x89, 0x9F, 0x8C, 0xF4,
	0x0D, 0xC5, 0xE5, 0x1F, 0xA1, 0x52, 0xC3, 0x4B,
	0x5C, 0x4C, 0xDF, 0x14, 0x05, 0x6A, 0xA8, 0xD7,
	0xAD, 0x4F, 0x22, 0xA6, 0xB8, 0xF9, 0x52, 0x5A,
	0xB8, 0xF9, 0xE2, 0x2C, 0x05, 0x2A, 0x6F, 0xF2,
	0xCA, 0xA1, 0xA7, 0xC3, 0x56, 0xE1, 0xDB, 0xC1,
	0xDB, 0x86, 0x26, 0x55, 0xAC, 0xBE, 0xE1, 0x3D,
	0x82, 0x86, 0xB9, 0xDE, 0x3E, 0xD3, 0x11, 0xAB,
	0x65, 0x6A, 0xED, 0x1B, 0x60, 0xBE, 0x69, 0x71,
	0xB2, 0xA8, 0x5B, 0xB1, 0x06, 0xE3, 0x48, 0x14,
	0xC9, 0x13, 0x73, 0xDA, 0xBE, 0xE4, 0x7A, 0x5F,
	0xC0, 0xE0, 0xCA, 0xF3, 0x7A, 0xCA, 0x3F, 0xC9,
	0x4A, 0xEE, 0x47, 0x76, 0x67, 0xF0, 0x0D, 0x3F,
	0x7F, 0x3D, 0x69, 0xEA, 0x39, 0x53, 0x7C, 0xE3,
	0xED, 0x78, 0x79, 0x47, 0x60, 0x95, 0xCB, 0xDC,
	0x26, 0x60, 0x46, 0xAC, 0x47, 0xDA, 0x4C, 0x4D,
	0x0F, 0xE1, 0x68, 0x43, 0xBC, 0xCD, 0x4E, 0xFE,
	0x2E, 0xD6, 0xC2, 0x6E, 0x63, 0xEA, 0xB3, 0x98,
	0xCA, 0x8F, 0x7F, 0x05, 0xDF, 0x72, 0x8F, 0x6E,
	0x3E, 0x6D, 0xC7, 0x94, 0x59, 0x9D, 0x15, 0x5B,
	0xB8, 0x02, 0x52, 0x4F, 0x68, 0x3A, 0xF1, 0xFF,
	0xA9, 0xA4, 0x30, 0x29, 0xE0, 0x1C, 0xA0, 0x1B,
	0x50, 0xAB, 0xFD, 0x06, 0x84, 0xD4, 0x33, 0x51,
	0x01, 0xB3, 0x5F, 0x49, 0x5F, 0x21, 0xA0, 0xA1,
	0xC9, 0x08, 0xB3, 0xDF, 0x72, 0x9B, 0x5B, 0x70,
	0x89, 0x96, 0x08, 0x25, 0x88, 0x1E, 0xED, 0x52,
	0xDC, 0x98, 0xA0, 0xB8, 0x83, 0x2A, 0xA0, 0x90,
	0x45, 0xC9, 0x77, 0xD2, 0x19, 0xD7, 0x6B, 0xAB,
	0x49, 0x67, 0x7C, 0xD1, 0xE0, 0x23, 0xA2, 0x36,
	0xB2, 0x91, 0x3B, 0x23, 0x3B, 0x03, 0x36, 0xAF,
	0xAD, 0x81, 0xFA, 0x6F, 0x68, 0xD5, 0xBE, 0x73,
	0x1D, 0x56, 0x8A, 0xE8, 0x1A, 0xB4, 0xA8, 0x7C,
	0xF3, 0x82, 0x10, 0xD0, 0xF2, 0x1D, 0x9C, 0xEA,
	0xAB, 0xE7, 0xEC, 0x53, 0x6D, 0x52, 0xBD, 0x29,
	0x86, 0x21, 0xCE, 0xAA, 0xF3, 0x68, 0xA6, 0xEC,
	0x7E, 0xCA, 0x6F, 0xEB, 0xE1, 0x81, 0x80, 0x7C,
	0xF3, 0xE5, 0x22, 0xA0, 0x91, 0x08, 0xB7, 0x35,
	0x15, 0x87, 0x0C, 0x77, 0x31, 0x9C, 0x2F, 0x73,
	0xCE, 0x29, 0x6F, 0xC6, 0xAC, 0x9F, 0x68, 0xB8,
	0x6A, 0xFC, 0xD3, 0xB5, 0x08, 0x98, 0xAE, 0xE4,
	0x20, 0x84, 0x24, 0x69, 0xA5, 0xF5, 0x4A, 0x9D,
	0x44, 0x26, 0x5A, 0xF9, 0x6B, 0x5E, 0x5D, 0xC8,
	0x6F, 0xD4, 0x62, 0x91, 0xE5, 0x8E, 0x80, 0x05,
	0xA1, 0x95, 0x09, 0xEA, 0xFE, 0x84, 0x6D, 0xC3,
	0x0D, 0xD4, 0x32, 0xA4, 0x38, 0xB2, 0xF7, 0x9D,
	0x58, 0xD3, 0x5D, 0x93, 0x5F, 0x67, 0x86, 0xE1,
	0xAF, 0xFF, 0xE9, 0xFE, 0xF4, 0x71, 0x63, 0xE3,
	0x3E, 0xE1, 0x7A, 0x80, 0x5A, 0x23, 0x4F, 0x5B,
	0x54, 0x21, 0x0E, 0xE2, 0xAF, 0x01, 0x2E, 0xA4,
	0xF5, 0x1F, 0x59, 0x96, 0x3E, 0x82, 0xF3, 0x44,
	0xDF, 0xA6, 0x7C, 0x64, 0x5D, 0xC7, 0x79, 0xA1,
	0x17, 0xE1, 0x06, 0x14, 0x3E, 0x1B, 0x46, 0xCA,
	0x71, 0xC8, 0x05, 0x62, 0xD0, 0x56, 0x23, 0x9B,
	0xBA, 0xFE, 0x6D, 0xA8, 0x03, 0x4C, 0x23, 0xD8,
	0x98, 0x8A, 0xE8, 0x9C, 0x93, 0x8E, 0xB7, 0x24,
	0x31, 0x2A, 0x81, 0x72, 0x8F, 0x13, 0xD4, 0x7E,
	0xEB, 0xB1, 0xEE, 0x33, 0xD9, 0xF4, 0x96, 0x5E,
	0x6C, 0x3D, 0x45, 0x9C, 0xE0, 0x71, 0xA3, 0xFA,
	0x17, 0x2B, 0xC3, 0x07, 0xD6, 0x86, 0xA2, 0x06,
	0xC5, 0x33, 0xF0, 0xEA, 0x25, 0x70, 0x68, 0x56,
	0xD5, 0xB0
};

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	gbl_args->exit_threads = 1;
}

static inline void init_packet(odp_packet_t pkt, uint32_t seq, uint16_t group)
{
	uint32_t *payload;
	test_hdr_t *hdr;
	odp_packet_parse_param_t param;

	param.proto = ODP_PROTO_ETH;
	param.last_layer = ODP_PROTO_LAYER_ALL;
	param.chksums.all_chksum = 0;
	if (odp_packet_parse(pkt, 0, &param))
		ODPH_ABORT("odp_packet_parse() failed\n");

	/* Modify UDP payload and update checksum */
	payload = odp_packet_offset(pkt, odp_packet_l4_offset(pkt) +
				    ODPH_UDPHDR_LEN, NULL, NULL);
	*payload = seq;
	if (odph_udp_chksum_set(pkt))
		ODPH_ABORT("odph_udp_chksum_set() failed\n");

	/* Test header is stored in user area */
	hdr = odp_packet_user_area(pkt);
	hdr->seq = seq;
	hdr->group = group;
	hdr->crc = odp_hash_crc32c(odp_packet_data(pkt), odp_packet_len(pkt),
				   CRC_INIT_VAL);
}

static inline odp_queue_t work_on_event(odp_event_t event)
{
	odp_packet_t pkt;
	odp_packet_parse_param_t param;
	odph_udphdr_t *udp_hdr;
	test_hdr_t *hdr;
	lookup_entry_t *lookup_entry;
	uint32_t *payload;
	uint32_t crc;
	uint32_t pkt_len;
	uint8_t *data;
	uint32_t new_val;
	uint32_t old_val;

	if (odp_event_type(event) != ODP_EVENT_PACKET)
		return ODP_QUEUE_INVALID;

	pkt = odp_packet_from_event(event);
	hdr = odp_packet_user_area(pkt);
	pkt_len = odp_packet_len(pkt);
	data = odp_packet_data(pkt);

	crc = odp_hash_crc32c(data, pkt_len, CRC_INIT_VAL);
	if (crc != hdr->crc)
		ODPH_ERR("Error: Invalid packet crc\n");

	param.proto = ODP_PROTO_ETH;
	param.last_layer = ODP_PROTO_LAYER_ALL;
	param.chksums.all_chksum = 1;
	if (odp_packet_parse(pkt, 0, &param)) {
		ODPH_ERR("Error: odp_packet_parse() failed\n");
		return ODP_QUEUE_INVALID;
	}

	/* Modify packet data using lookup table value and sequence number, and
	 * update UDP checksum accordingly. */
	lookup_entry = &gbl_args->lookup_tbl[(crc + hdr->seq) %
					     gbl_args->appl.lookup_tbl_size];
	udp_hdr = odp_packet_l4_ptr(pkt, NULL);
	payload = odp_packet_offset(pkt, odp_packet_l4_offset(pkt) +
				    ODPH_UDPHDR_LEN, NULL, NULL);
	old_val = *payload;
	*payload += lookup_entry->idx % 2 ? lookup_entry->val1 :
			lookup_entry->val0;
	new_val = *payload;
	udp_hdr->chksum = ~(~udp_hdr->chksum + (-old_val) + new_val);

	payload++;
	old_val =  *payload;
	*payload += hdr->seq;
	new_val = *payload;
	udp_hdr->chksum = ~(~udp_hdr->chksum + (-old_val) + new_val);

	hdr->crc = odp_hash_crc32c(data, pkt_len, CRC_INIT_VAL);

	return gbl_args->queue[hdr->group][hdr->seq++ % QUEUES_PER_GROUP];
}

/**
 * Worker thread
 */
static int run_thread(void *arg)
{
	thread_args_t *thr_args = arg;
	stats_t *stats = &thr_args->stats;
	odp_time_t t1, t2;
	uint64_t c1, c2;

	odp_barrier_wait(&gbl_args->init_barrier);

	c1 = odp_cpu_cycles();
	t1 = odp_time_local();

	while (!gbl_args->exit_threads) {
		odp_event_t  event_tbl[MAX_EVENT_BURST];
		odp_queue_t dst_queue;
		int num_events;
		int i;

		num_events = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
						event_tbl, MAX_EVENT_BURST);
		if (num_events <= 0)
			continue;

		for (i = 0; i < num_events; i++) {
			odp_event_t  event = event_tbl[i];

			dst_queue = work_on_event(event);
			if (odp_unlikely(dst_queue == ODP_QUEUE_INVALID)) {
				stats->s.dropped_pkts++;
				odp_event_free(event);
				continue;
			}

			if (odp_unlikely(odp_queue_enq(dst_queue, event))) {
				ODPH_ERR("Error: odp_queue_enq() failed\n");
				stats->s.dropped_pkts++;
				odp_event_free(event);
				break;
			}

			stats->s.pkts++;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	stats->s.cycles = c2 - c1;
	stats->s.nsec = odp_time_diff_ns(t2, t1);

	odp_barrier_wait(&gbl_args->term_barrier);

	/* Free remaining events in queues */
	while (1) {
		odp_event_t  ev;

		ev = odp_schedule(NULL,
				  odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	return 0;
}

/*
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane CPU benchmarking application.\n"
	       "\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "  E.g. %s -c 4 -t 30\n"
	       "Options:\n"
	       "  -c, --count <number> CPU count, 0=all available, default=1\n"
	       "  -t, --time <sec>        Time in seconds to run\n"
	       "                          (default is 10 second).\n"
	       "  -a, --accuracy <sec>    Time in seconds get print statistics\n"
	       "                          (default is 1 second).\n"
	       "  -l, --lookup_tbl <num>  Number of entries in dummy lookup table\n"
	       "                          (default is %d).\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), DEF_LOOKUP_TBL_SIZE);
}

/**
 * @internal Parse arguments
 *
 * @param argc  Argument count
 * @param argv  Argument vector
 * @param args  Test arguments
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;

	static const struct option longopts[] = {
		{"accuracy", required_argument, NULL, 'a'},
		{"cpu", required_argument, NULL, 'c'},
		{"lookup_tbl", required_argument, NULL, 'l'},
		{"time", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:c:l:t:h";

	appl_args->accuracy = 1; /* Get and print pps stats second */
	appl_args->cpu_count = 1;
	appl_args->lookup_tbl_size = DEF_LOOKUP_TBL_SIZE;
	appl_args->time = 10; /* Loop forever if time to run is 0 */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'a':
			appl_args->accuracy = atoi(optarg);
			break;
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'l':
			appl_args->lookup_tbl_size = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->lookup_tbl_size < 1) {
		printf("At least one lookup table entry required.\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Print statistics
 *
 * num_workers Number of worker threads
 * thr_stats   Pointers to stats storage
 * duration    Number of seconds to loop
 */
static int print_stats(int num_workers, stats_t **thr_stats, int duration,
		       int accuracy)
{
	uint64_t pkts;
	uint64_t dropped;
	uint64_t pkts_prev = 0;
	uint64_t nsec = 0;
	uint64_t cycles = 0;
	int i;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);

	if (accuracy <= 0) {
		stats_enabled = 0;
		accuracy = 1;
	}
	/* Wait for all threads to be ready*/
	odp_barrier_wait(&gbl_args->init_barrier);

	do {
		uint64_t pps;

		sleep(accuracy);

		pkts = 0;
		dropped = 0;
		for (i = 0; i < num_workers; i++) {
			pkts += thr_stats[i]->s.pkts;
			dropped += thr_stats[i]->s.dropped_pkts;
		}

		pps = (pkts - pkts_prev) / accuracy;

		if (stats_enabled) {
			printf("%.2f Mpps, ", pps / 1000000.0);

			printf("%" PRIu64 " dropped\n", dropped);
		}

		pkts_prev = pkts;
		elapsed += accuracy;
	} while (!gbl_args->exit_threads &&
		 (loop_forever || (elapsed < duration)));

	gbl_args->exit_threads = 1;
	odp_barrier_wait(&gbl_args->term_barrier);

	pkts = 0;
	dropped = 0;
	for (i = 0; i < num_workers; i++) {
		pkts += thr_stats[i]->s.pkts;
		dropped += thr_stats[i]->s.dropped_pkts;
		nsec +=  thr_stats[i]->s.nsec;
		cycles += thr_stats[i]->s.cycles;
	}

	printf("\nRESULTS - per thread (Million packets per sec):\n");
	printf("-----------------------------------------------\n");
	printf("  avg    1      2      3      4      5      6      7      8      9      10\n");
	printf("%6.2f ", pkts / (nsec / 1000.0));

	for (i = 0; i < num_workers; i++) {
		if (i != 0 && (i % 10) == 0)
			printf("\n       ");

		printf("%6.2f ", thr_stats[i]->s.pkts /
		       (thr_stats[i]->s.nsec / 1000.0));
	}
	printf("\n\n");

	nsec /= num_workers;
	printf("RESULTS - total over %i threads:\n", num_workers);
	printf("----------------------------------\n");
	printf("  avg packets per sec:   %.3f M\n", pkts / (nsec / 1000.0));
	printf("  avg cycles per packet: %" PRIu64 "\n", cycles / pkts);
	printf("  dropped packets:       %" PRIu64 "\n\n", dropped);

	return pkts > PASS_PACKETS ? 0 : -1;
}

static void gbl_args_init(args_t *args)
{
	memset(args, 0, sizeof(args_t));
}

/**
 * Test main function
 */
int main(int argc, char *argv[])
{
	stats_t *stats[MAX_WORKERS];
	odph_helper_options_t helper_options;
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_cpumask_t cpumask;
	odp_pool_capability_t pool_capa;
	odp_pool_t pool;
	odp_schedule_config_t schedule_config;
	odp_shm_t shm;
	odp_shm_t lookup_tbl_shm;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_init_t init;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	uint32_t num_pkts;
	uint32_t num_groups;
	uint32_t num_queues;
	uint32_t pkts_per_group;
	uint32_t pkt_len;
	uint32_t init_val;
	unsigned int num_workers;
	unsigned int i, j;
	int cpu;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init);

	/* List features not to be used (may optimize performance) */
	init.not_used.feat.cls    = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec  = 1;
	init.not_used.feat.timer  = 1;
	init.not_used.feat.tm     = 1;

	init.mem_model = helper_options.mem_model;

	/* Signal handler has to be registered before global init in case ODP
	 * implementation creates internal threads/processes. */
	signal(SIGINT, sig_handler);

	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Error: ODP global init failed\n");
		return -1;
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE,
			      0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	lookup_tbl_shm = odp_shm_reserve("lookup_tbl_shm",
					 sizeof(lookup_entry_t) *
					 gbl_args->appl.lookup_tbl_size,
					 ODP_CACHE_LINE_SIZE, 0);
	if (lookup_tbl_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args->lookup_tbl = odp_shm_addr(lookup_tbl_shm);
	if (gbl_args->lookup_tbl == NULL) {
		ODPH_ERR("Error: lookup table mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	printf("\n");
	odp_sys_info_print();

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count && gbl_args->appl.cpu_count < MAX_WORKERS)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	odp_schedule_config_init(&schedule_config);
	odp_schedule_config(&schedule_config);

	/* Make sure a single queue can store all the packets in a group */
	pkts_per_group = QUEUES_PER_GROUP * PKTS_PER_QUEUE;
	if (schedule_config.queue_size  &&
	    schedule_config.queue_size < pkts_per_group)
		pkts_per_group = schedule_config.queue_size;

	/* Divide queues evenly into groups */
	if (schedule_config.num_queues < QUEUES_PER_GROUP) {
		ODPH_ERR("Error: min %d queues required\n", QUEUES_PER_GROUP);
		return -1;
	}
	num_queues = num_workers > schedule_config.num_queues ?
			schedule_config.num_queues : num_workers;
	num_groups = (num_queues + QUEUES_PER_GROUP - 1) / QUEUES_PER_GROUP;
	if (num_groups * QUEUES_PER_GROUP > schedule_config.num_queues)
		num_groups--;
	num_queues = num_groups * QUEUES_PER_GROUP;

	for (i = 0; i < num_groups; i++) {
		for (j = 0; j < QUEUES_PER_GROUP; j++) {
			odp_queue_t queue;
			odp_queue_param_t param;

			odp_queue_param_init(&param);
			param.type        = ODP_QUEUE_TYPE_SCHED;
			param.sched.prio  = ODP_SCHED_PRIO_NORMAL;
			param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
			param.sched.group = ODP_SCHED_GROUP_ALL;
			param.size = pkts_per_group;

			queue = odp_queue_create(NULL, &param);
			if (queue == ODP_QUEUE_INVALID) {
				ODPH_ERR("Error: odp_queue_create() failed\n");
				return -1;
			}
			gbl_args->queue[i][j] = queue;
		}
	}

	/* Create packet pool */
	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Error: odp_pool_capability() failed\n");
		exit(EXIT_FAILURE);
	}
	num_pkts = pkts_per_group * num_groups;
	if (num_pkts > pool_capa.pkt.max_num)
		num_pkts = pool_capa.pkt.max_num;

	pkt_len = sizeof(test_udp_packet);
	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len)
		pkt_len = pool_capa.pkt.max_len;

	if (pool_capa.pkt.max_seg_len && pkt_len > pool_capa.pkt.max_seg_len)
		pkt_len = pool_capa.pkt.max_seg_len;

	if (pkt_len < sizeof(test_udp_packet)) {
		ODPH_ERR("Error: min %dB single segment packets required\n",
			 (int)sizeof(test_udp_packet));
		exit(EXIT_FAILURE);
	}

	if (pool_capa.pkt.max_uarea_size &&
	    pool_capa.pkt.max_uarea_size < sizeof(test_hdr_t)) {
		ODPH_ERR("Error: min %dB of packet user area required\n",
			 (int)sizeof(test_hdr_t));
		exit(EXIT_FAILURE);
	}

	odp_pool_param_init(&params);
	params.pkt.len = pkt_len;
	params.pkt.max_len = pkt_len;
	params.pkt.seg_len = pkt_len;
	params.pkt.num = num_pkts;
	params.pkt.max_num = num_pkts;
	params.pkt.uarea_size = sizeof(test_hdr_t);
	params.type = ODP_POOL_PACKET;
	pool = odp_pool_create("pkt_pool", &params);
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	printf("CPU bench args\n--------------\n");
	printf("  workers:        %u\n", num_workers);
	printf("  queues:         %" PRIu32 "\n", num_queues);
	printf("  pkts:           %" PRIu32 "\n", num_pkts);
	printf("  pkt size:       %" PRIu32 " B\n", pkt_len);
	printf("  lookup entries: %" PRIu64 "\n\n",
	       gbl_args->appl.lookup_tbl_size);

	/* Spread test packets into queues */
	for (i = 0; i < num_pkts; i++) {
		odp_packet_t pkt = odp_packet_alloc(pool, pkt_len);
		odp_event_t ev;
		odp_queue_t queue;
		uint16_t group = i % num_groups;

		if (pkt == ODP_PACKET_INVALID) {
			ODPH_ERR("Error: odp_packet_alloc() failed\n");
			return -1;
		}

		odp_packet_copy_from_mem(pkt, 0, pkt_len, test_udp_packet);

		init_packet(pkt, i, group);

		queue = gbl_args->queue[group][i % QUEUES_PER_GROUP];

		ev = odp_packet_to_event(pkt);
		if (odp_queue_enq(queue, ev)) {
			ODPH_ERR("Error: odp_queue_enq() failed\n");
			return -1;
		}
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	odp_barrier_init(&gbl_args->init_barrier, num_workers + 1);
	odp_barrier_init(&gbl_args->term_barrier, num_workers + 1);

	/* Initialize lookup table */
	init_val = CRC_INIT_VAL;
	for (i = 0; i < gbl_args->appl.lookup_tbl_size; i++) {
		uint32_t *val0 = &gbl_args->lookup_tbl[i].val0;
		uint32_t *val1 = &gbl_args->lookup_tbl[i].val1;

		gbl_args->lookup_tbl[i].idx = i;

		*val0 = i;
		*val0 = odp_hash_crc32c(val0, sizeof(uint32_t), init_val);
		*val1 = odp_hash_crc32c(val0, sizeof(uint32_t), init_val);
		init_val = *val1;
	}

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; i++) {
		odp_cpumask_t thd_mask;
		odph_odpthread_params_t thr_params;

		gbl_args->thread[i].idx = i;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = run_thread;
		thr_params.arg      = &gbl_args->thread[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		stats[i] = &gbl_args->thread[i].stats;

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_odpthreads_create(&thread_tbl[i], &thd_mask,
				       &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	ret = print_stats(num_workers, stats, gbl_args->appl.time,
			  gbl_args->appl.accuracy);

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	for (i = 0; i < num_groups; i++) {
		for (j = 0; j < QUEUES_PER_GROUP; j++) {
			if (odp_queue_destroy(gbl_args->queue[i][j])) {
				ODPH_ERR("Error: queue destroy\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	gbl_args = NULL;
	odp_mb_full();

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(lookup_tbl_shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}
