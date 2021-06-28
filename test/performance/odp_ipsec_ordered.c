/* Copyright (c) 2021, Marvell
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define app_err(fmt, ...) \
	fprintf(stderr, "%s:%d:%s(): Error: " fmt, __FILE__, \
			__LINE__, __func__, ##__VA_ARGS__)

/** @def POOL_NUM_PKT
 * Number of packets in the pool
 */
#define POOL_NUM_PKT  4096

static uint8_t test_salt[16] = "0123456789abcdef";

static uint8_t test_key16[16] = { 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10,
};

static uint8_t test_key20[20] = { 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14,
};

static uint8_t test_key24[24] = { 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18
};

static uint8_t test_key32[32] = { 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
	0x1f, 0x20,
};

static uint8_t test_key64[64] = { 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19,
	0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
	0x1f, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x4b, 0x2c, 0x2d,
	0x2e, 0x2f, 0x30, 0x31, 0x32,
	0x33, 0x34, 0x55, 0x36, 0x37,
	0x38, 0x39, 0x5a, 0x3b, 0x3c,
	0x3d, 0x3e, 0x5f, 0x40,
};

#define MAX_EVENT_BURST 32
/**
 * Structure that holds template for sa create call
 * for different algorithms supported by test
 */
typedef struct {
	const char *name;                     /**< Algorithm name */
	odp_ipsec_crypto_param_t crypto; /**< Prefilled SA crypto param */
} ipsec_alg_config_t;

/**
 * Parsed command line crypto arguments. Describes test configuration.
 */
typedef struct {
	/**
	 * If non zero prints content of packets. Enabled by -d or
	 * --debug option.
	 */
	int debug_packets;

	/**
	 * Maximum number of outstanding encryption requests. Note code
	 * poll for results over queue and if nothing is available it can
	 * submit more encryption requests up to maximum number specified by
	 * this option. Specified through -f or --flight option.
	 */
	uint32_t in_flight;

	/**
	 * Number of iteration to repeat crypto operation to get good
	 * average number. Specified through -i or --terations option.
	 * Default is 10000.
	 */
	int iteration_count;

	/**
	 * Payload size to test. If 0 set of predefined payload sizes
	 * is tested. Specified through -p or --payload option.
	 */
	unsigned int payload_length;

	/**
	 * Pointer to selected algorithm to test. If NULL all available
	 * alogorthims are tested. Name of algorithm is passed through
	 * -a or --algorithm option.
	 */
	ipsec_alg_config_t *alg_config;

	/*
	 * Number of worker cores that will process the packets
	 * in parallel.
	 */
	int num_workers;

	/*
	 * Enable workers to read events from Queue in
	 * max burst of 32
	 */
	int burst;

	/*
	 * Queue modes: parallel, atomic, ordered
	 * */
	int sched_sync;
	/*
	 * Use tunnel instead of transport mode.
	 * Specified through -t argument.
	 */
	int tunnel;

	/*
	 * Use AH transformation.
	 * Specified through -u argument.
	 */
	int ah;
} ipsec_args_t;

/*
 * Helper structure that holds averages for test of one algorithm
 * for given payload size.
 */
typedef struct ODP_ALIGNED_CACHE {
	/**
	 * Elapsed time for one crypto operation.
	 */
	double elapsed;

	/**
	 * Packets processed by this thread
	 */
	double packet_count;
	/**
	 * Marked valid if this CPU is used for testing
	 */
	bool valid;
	/**
	 * lcore ID
	 */
	int cpu_id;

} ipsec_run_result_t;

/**
 * Structure holds one snap to misc times of current process.
 */
typedef struct {
	struct timeval tv;       /**< Elapsed time */
	struct rusage ru_self;   /**< Rusage value for whole process */
	struct rusage ru_thread; /**< Rusage value for current thread */
} time_record_t;

/**
 * Set of predefined payloads.
 */
static unsigned int global_payloads[] = {
	64,
	256,
	1024,
	8192,
	16384
};

/** Number of payloads used in the test */
static unsigned int global_num_payloads;

/**
 * Set of known algorithms to test
 */
static ipsec_alg_config_t algs_config[] = {
	{
		.name = "3des-cbc-null",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_3DES_CBC,
			.cipher_key = {
				.data = test_key24,
				.length = sizeof(test_key24)
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},

	{
		.name = "3des-cbc-hmac-md5-96",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_3DES_CBC,
			.cipher_key = {
				.data = test_key24,
				.length = sizeof(test_key24)
			},
			.auth_alg = ODP_AUTH_ALG_MD5_HMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
		},
	},
	{
		.name = "null-hmac-md5-96",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_MD5_HMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
		},
	},
	{
		.name = "aes-cbc-null",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CBC,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},
	{
		.name = "aes-cbc-hmac-sha1-96",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CBC,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
		},
	},
	{
		.name = "aes-ctr-null",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CTR,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_key_extra = {
				.data = test_salt,
				.length = 4,
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},
	{
		.name = "aes-ctr-hmac-sha1-96",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CTR,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_key_extra = {
				.data = test_salt,
				.length = 4,
			},
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
		},
	},
	{
		.name = "null-hmac-sha1-96",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
		},
	},
	{
		.name = "null-hmac-sha256-128",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA256_HMAC,
			.auth_key = {
				.data = test_key32,
				.length = sizeof(test_key32)
			},
		},
	},
	{
		.name = "null-hmac-sha512-256",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA512_HMAC,
			.auth_key = {
				.data = test_key64,
				.length = sizeof(test_key64)
			},
		},
	},
	{
		.name = "null-aes-gmac",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_AES_GMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_key_extra = {
				.data = test_salt,
				.length = 4,
			},
		},
	},
	{
		.name = "aes-gcm",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_GCM,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_key_extra = {
				.data = test_salt,
				.length = 4,
			},
			.auth_alg = ODP_AUTH_ALG_AES_GCM,
		},
	},
	{
		.name = "aes-ccm",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CCM,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_key_extra = {
				.data = test_salt,
				.length = 3,
			},
			.auth_alg = ODP_AUTH_ALG_AES_CCM,
		},
	},
	{
		.name = "chacha20-poly1305",
		.crypto = {
			.cipher_alg = ODP_CIPHER_ALG_CHACHA20_POLY1305,
			.cipher_key = {
				.data = test_key32,
				.length = sizeof(test_key32)
			},
			.cipher_key_extra = {
				.data = test_salt,
				.length = 4,
			},
			.auth_alg = ODP_AUTH_ALG_CHACHA20_POLY1305,
		},
	},
};

#define MAX_WORKERS 128
#define NUM_CONFIGS             (sizeof(algs_config) / sizeof(ipsec_alg_config_t))

/**
 * Grouping of all global data
 */
typedef struct {
	ipsec_args_t cargs;
	odp_instance_t instance;

	/** Break workers loop if set to 1 */
	odp_atomic_u32_t exit_threads;
	odp_atomic_u32_t in_queue_count;
	odp_atomic_u32_t complete_cnt;
	odp_atomic_u32_t pkt_alloc;
	odp_atomic_u32_t pkt_free;
	int num_workers;
	odp_pool_t pkt_pool;
	odp_queue_t in_queue;
	ipsec_run_result_t result[MAX_WORKERS];
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_ipsec_sa_t sa[MAX_EVENT_BURST];
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

#define MAX_WORKERS 128
#define	NUM_CONFIGS		(sizeof(algs_config) / sizeof(ipsec_alg_config_t))

/**
 * Get the Result data for the calling thread
 */
static ipsec_run_result_t *cpu_get_result(void)
{
	int cpu = odp_cpu_id();

	if (cpu >= MAX_WORKERS)
		exit(EXIT_FAILURE);

	return &gbl_args->result[cpu];
}

/**
 * Initialize applicaiton parameters
 */
static void
gbl_args_init(args_t *args)
{
	memset(args, 0, sizeof(args_t));

	odp_atomic_init_u32(&args->exit_threads, 0);
	odp_atomic_init_u32(&args->in_queue_count, 0);
	odp_atomic_init_u32(&args->complete_cnt, 0);
	odp_atomic_init_u32(&args->pkt_alloc, 0);
	odp_atomic_init_u32(&args->pkt_free, 0);
}

/**
 * Find corresponding config for given name. Returns NULL
 * if config for given name is not found.
 */
static ipsec_alg_config_t *
find_config_by_name(const char *name)
{
	unsigned int i;
	ipsec_alg_config_t *ret = NULL;

	for (i = 0; i < NUM_CONFIGS; i++) {
		if (strcmp(algs_config[i].name, name) == 0) {
			ret = algs_config + i;
			break;
		}
	}
	return ret;
}

/**
 * Helper function that prints list of algorithms that this
 * test understands.
 */
static void
print_config_names(const char *prefix)
{
	unsigned int i;

	for (i = 0; i < (sizeof(algs_config) / sizeof(ipsec_alg_config_t));
			i++) {
		printf("%s %s\n", prefix, algs_config[i].name);
	}
}

/**
 * Print header line for our report.
 */
static void
print_result_header(void)
{
	printf("\n%10s %30.30s %20s %15s %15s %15s\n",
	       "cpu", "algorithm", "payload (bytes)", "Pkt Count", "elapsed (us)",
			"throughput (Kb)");
}

/**
 * Print header line for our report.
 */
static void
print_summary_header(void)
{
	printf("%10s %30.30s %20s %15s %15s %15s\n",
	       "summary", " ", " ", "total", "max",
			"total");
}

/**
 * Print one line of our report.
 */
static void
print_results(ipsec_args_t *cargs,
	      unsigned int payload_length,
		ipsec_alg_config_t *config)
{
	int cpu;
	unsigned int throughput_total = 0;
	ipsec_run_result_t result_total;

	memset(&result_total, 0, sizeof(result_total));

	for (cpu = 0; cpu < MAX_WORKERS; cpu++)	{
		unsigned int throughput;
		ipsec_run_result_t *result;

		result = &gbl_args->result[cpu];

		if (result->packet_count == 0)
			continue;

		result->elapsed = (result->elapsed / result->packet_count) / 1000;
		throughput = (1000000.0 / result->elapsed) * payload_length / 1024;

		/* This core's data */
		printf("%10d %30.30s %20d %15.0f %15.3f %15d\n",
		       cpu, config->name, payload_length, result->packet_count,
				result->elapsed, throughput);

		result_total.elapsed = result_total.elapsed > result->elapsed ?
			result_total.elapsed : result->elapsed;
		result_total.packet_count += result->packet_count;
		throughput_total += throughput;
	}

	/* Print Summary */
	if (cargs->num_workers > 1) {
		print_summary_header();
		printf("%10s %30.30s %20s %15.0f %15.3f %15d\n\n",
		       "", " ", " ", result_total.packet_count,
				result_total.elapsed,
				throughput_total);
	}
}

#define IPV4ADDR(a, b, c, d) odp_cpu_to_be_32((a << 24) | \
		(b << 16) | \
		(c << 8) | \
		(d << 0))
/**
 * Create ODP IPsec SA for given config.
 */
static odp_ipsec_sa_t
create_sa_from_config(ipsec_alg_config_t *config,
		      ipsec_args_t *cargs)
{
	odp_ipsec_sa_param_t param;

	odp_ipsec_sa_param_init(&param);
	memcpy(&param.crypto, &config->crypto,
	       sizeof(odp_ipsec_crypto_param_t));

	param.proto = ODP_IPSEC_ESP;
	param.dir = ODP_IPSEC_DIR_OUTBOUND;

	if (cargs->tunnel) {
		uint32_t src = IPV4ADDR(10, 0, 111, 2);
		uint32_t dst = IPV4ADDR(10, 0, 222, 2);
		odp_ipsec_tunnel_param_t tunnel;

		memset(&tunnel, 0, sizeof(tunnel));
		tunnel.type = ODP_IPSEC_TUNNEL_IPV4;
		tunnel.ipv4.src_addr = &src;
		tunnel.ipv4.dst_addr = &dst;
		tunnel.ipv4.ttl = 64;

		param.mode = ODP_IPSEC_MODE_TUNNEL;
		param.outbound.tunnel = tunnel;
	} else {
		param.mode = ODP_IPSEC_MODE_TRANSPORT;
	}

	param.dest_queue = ODP_QUEUE_INVALID;

	return odp_ipsec_sa_create(&param);
}

static uint8_t test_data[] = {
	/* IP */
	0x45, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x01, 0xac, 0x27, 0xc0, 0xa8, 0x6f, 0x02,
	0xc0, 0xa8, 0xde, 0x02,

	/* ICMP */
	0x08, 0x00, 0xfb, 0x37, 0x12, 0x34, 0x00, 0x00
};

/**
 * Worker thread
 *
 * @param arg      Thread arguments of type 'odp_ipsec_sa_t'
 */
static int
run_worker(void *arg ODP_UNUSED)
{
	odp_event_t  ev_tbl[MAX_EVENT_BURST];
	int rc;
	odp_ipsec_out_param_t param;
	ipsec_args_t *cargs;
	int max_burst = 1;

	cargs = &gbl_args->cargs;

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));
	param.num_sa = 1;
	param.num_opt = 0;
	param.sa = &gbl_args->sa[0];
	ipsec_run_result_t *result;

	result = cpu_get_result();
	result->packet_count = 0;

	if (cargs->burst)
		max_burst = MAX_EVENT_BURST;

	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
		odp_packet_t pkt;
		odp_packet_t out_pkt;
		int num_out = 1;
		odp_time_t start, end;
		int num_events;
		int i;

		num_events = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
						ev_tbl, max_burst);

		if (num_events <= 0)
			continue;

		for (i = 0; i < num_events; i++) {
			odp_event_t  event = ev_tbl[i];

			if (event == ODP_EVENT_INVALID)
				continue;

			result->packet_count++;
			odp_atomic_fetch_sub_u32(&gbl_args->in_queue_count, 1);
			pkt = odp_packet_from_event(event);

			if (cargs->debug_packets)
				odp_packet_print_data(pkt, 0, odp_packet_len(pkt));

			start = odp_time_local();

			rc = odp_ipsec_out(&pkt, 1, &out_pkt, &num_out, &param);

			if (rc <= 0) {
				app_err("failed odp_ipsec_out: rc = %d\n",
					rc);
				odp_packet_free(pkt);
				break;
			}

			if (odp_packet_has_error(out_pkt)) {
				odp_ipsec_packet_result_t result;

				odp_ipsec_result(&result, out_pkt);
				app_err("Received error packet: %d\n",
					result.status.error.all);
			}

			end = odp_time_local();

			result->elapsed += odp_time_diff_ns(end, start);

			if (cargs->debug_packets)
				odp_packet_print_data(out_pkt, 0,
						      odp_packet_len(out_pkt));

			/* Free the packet */
			odp_packet_free(out_pkt);

			odp_atomic_fetch_add_u32(&gbl_args->pkt_free, 1);
			odp_atomic_fetch_sub_u32(&gbl_args->complete_cnt, 1);
		}
	}

	return 0;
}

/* Create worker threads */
static int
create_workers(int count)
{
	int cpu;
	int num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	int i;
	odph_odpthread_t *thread_tbl = &gbl_args->thread_tbl[0];

	num_workers = count;
	if (num_workers > (ODP_THREAD_COUNT_MAX - 1)) {
		ODPH_ERR("Error: Max Workers %d greater than supported %d\n",
			 num_workers, (ODP_THREAD_COUNT_MAX - 1));
		exit(EXIT_FAILURE);
	}
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));
	printf("Num worker threads: %i\n", num_workers);
	printf("First CPU:                      %i\n", odp_cpumask_first(&cpumask));
	printf("CPU mask:                       %s\n\n", cpumaskstr);

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; i++) {
		odp_cpumask_t thd_mask;
		odph_odpthread_params_t thr_params;

		memset(&thr_params, 0, sizeof(thr_params));
		memset(&thread_tbl[i], 0, sizeof(odph_odpthread_t));

		thr_params.start = run_worker;
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = gbl_args->instance;

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_odpthreads_create(&thread_tbl[i], &thd_mask, &thr_params);

		gbl_args->result[cpu].valid = 1;
		gbl_args->result[cpu].cpu_id = cpu;

		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	return num_workers;
}

/**
 * Stop the worker loops and wait for the threads
 * to exit.
 */
static void
stop_workers(void)
{
	odph_odpthread_t *thread_tbl = &gbl_args->thread_tbl[0];

	/* Signal loop exit */
	odp_atomic_store_u32(&gbl_args->exit_threads, 1);

	odph_odpthreads_join(thread_tbl);
}

/**
 * Create packet for the given length
 */
static odp_packet_t
make_packet(unsigned int payload_length)
{
	odp_packet_t pkt;

	if (payload_length < sizeof(test_data))
		return ODP_PACKET_INVALID;

	pkt = odp_packet_alloc(gbl_args->pkt_pool, payload_length);

	if (pkt == ODP_PACKET_INVALID) {
		app_err("failed to allocate buffer\n");
		return pkt;
	}
	odp_atomic_add_u32(&gbl_args->pkt_alloc, 1);

	odp_packet_copy_from_mem(pkt, 0, sizeof(test_data), test_data);
	odp_packet_l3_offset_set(pkt, 0);

	uint8_t *mem = odp_packet_data(pkt);
	((odph_ipv4hdr_t *)mem)->tot_len = odp_cpu_to_be_16(payload_length);
	memset(mem + sizeof(test_data), 1, payload_length - sizeof(test_data));

	return pkt;
}

/**
 * Run measurement iterations for given config and payload size.
 * Result of run returned in 'result' out parameter.
 */
static int
send_one_packet_size(ipsec_args_t *cargs,
		     unsigned int payload_length)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_event_t event;
	int rc = 0;

	int packets_sent = 0;

	while (packets_sent < cargs->iteration_count)	{
		/* Wait, if workers are overloaded */
		while (odp_atomic_load_u32(&gbl_args->in_queue_count) > cargs->in_flight)
			;

		/* Allocate a packet for the test size */
		pkt = make_packet(payload_length);
		if (ODP_PACKET_INVALID == pkt)
			return -1;

		event = odp_packet_to_event(pkt);

		/* Enqueue packet to queue */
		rc = odp_queue_enq(gbl_args->in_queue, event);
		if (rc != 0) {
			app_err("ERROR:failed to enq pkt to input queue: rc = %d\n", rc);
			odp_packet_free(pkt);
			break;
		}

		/* Counters update */
		packets_sent++;
		odp_atomic_add_u32(&gbl_args->in_queue_count, 1);
		odp_atomic_add_u32(&gbl_args->complete_cnt, 1);
	}

	return rc < 0 ? rc : 0;
}

/**
 * Process one algorithm. Note if paload size is specicified it is
 * only one run. Or iterate over set of predefined payloads.
 */
static int
send_measure_one_config(ipsec_args_t *cargs,
			ipsec_alg_config_t *config)
{
	int rc = 0;
	unsigned int num_payloads = global_num_payloads;
	unsigned int *payloads = global_payloads;
	unsigned int i;

	if (cargs->payload_length) {
		num_payloads = 1;
		payloads = &cargs->payload_length;
	}

	for (i = 0; i < num_payloads; i++)	{
		memset(gbl_args->result, 0, sizeof(gbl_args->result));

		/* Reset packet count to zero for this round */
		odp_atomic_init_u32(&gbl_args->complete_cnt, 0);

		/* Generate and send packets for this workload size */
		rc = send_one_packet_size(cargs, payloads[i]);

		/* Wait for workers to complete pending work */
		while (odp_atomic_load_u32(&gbl_args->complete_cnt) != 0)
			;

		if (rc)	{
			printf("Run Measure %d failed for packet size [%d]\n ", i, payloads[i]);
			break;
		}

		/* Print the test summary */
		print_results(cargs, payloads[i], config);
	}

	return rc;
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
			"Usage: %s OPTIONS\n"
			"  E.g. %s -i 100000 -w 2\n"
			"\n"
			"OpenDataPlane crypto speed measure.\n"
			"Optional OPTIONS\n"
			"  -a, --algorithm <name> Specify algorithm name (default all)\n"
			"                         Supported values are:\n",
			progname, progname);

	print_config_names("                                  ");
	printf("  -d, --debug          Enable dump of processed packets.\n"
			"  -f, --flight <number> Max number of packet processed in parallel (default 1)\n"
			"  -i, --iterations <number> Number of iterations.\n"
			"  -l, --payload        Payload length.\n"
			"  -w, --workers        Number of Worker Cores.\n"
			"  -s, --sched	       queue sched mode 0:Parallel 1:Atomic 2:Ordered(default)\n"
			"  -t, --tunnel         Use tunnel-mode IPsec transformation.\n"
			"  -u, --ah             Use AH transformation instead of ESP.\n"
			"  -h, --help           Display help and exit.\n"
			"\n");
}

static void parse_args(int argc, char *argv[], ipsec_args_t *cargs)
{
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"algorithm", optional_argument, NULL, 'a'},
		{"debug",  no_argument, NULL, 'd'},
		{"flight", optional_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"iterations", optional_argument, NULL, 'i'},
		{"payload", optional_argument, NULL, 'l'},
		{"sessions", optional_argument, NULL, 'm'},
		{"workers", optional_argument, NULL, 'w'},
		{"sched", optional_argument, NULL, 's'},
		{"tunnel", no_argument, NULL, 't'},
		{"ah", no_argument, NULL, 'u'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:df:hi:l:m:s:w:t:u";

	cargs->in_flight = 64;
	cargs->debug_packets = 0;
	cargs->iteration_count = 10000;
	cargs->payload_length = 0;
	cargs->alg_config = NULL;
	cargs->num_workers = 1;
	cargs->ah = 0;
	cargs->burst = 0;
	cargs->sched_sync = ODP_SCHED_SYNC_ORDERED;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;  /* No more options */

		switch (opt) {
		case 'a':
			cargs->alg_config = find_config_by_name(optarg);
			if (!cargs->alg_config) {
				printf("cannot test crypto '%s' configuration\n",
				       optarg);
					usage(argv[0]);
					exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			cargs->debug_packets = 1;
			break;
		case 'i':
			cargs->iteration_count = atoi(optarg);
			break;
		case 'f':
			cargs->in_flight = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'l':
			cargs->payload_length = atoi(optarg);
			break;
		case 'w':
			cargs->num_workers = atoi(optarg);
			break;
		case 't':
			cargs->tunnel = 1;
			break;
		case 'u':
			cargs->ah = 1;
			break;
		case 's':
			cargs->sched_sync = atoi(optarg);
			if ((cargs->sched_sync != ODP_SCHED_SYNC_ORDERED) &&
			    (cargs->sched_sync != ODP_SCHED_SYNC_PARALLEL) &&
			    (cargs->sched_sync != ODP_SCHED_SYNC_ATOMIC)) {
				printf("Inavlud Sync Option %d\n", cargs->sched_sync);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			break;
		}
	}

	optind = 1;             /* reset 'extern optind' from the getopt lib */
}

int main(int argc, char *argv[])
{
	ipsec_args_t *cargs;
	odp_pool_t pool;
	odp_queue_param_t qparam;
	odp_schedule_capability_t schedule_capa;
	odp_schedule_config_t schedule_config;
	odp_pool_param_t param;
	odp_queue_t in_queue = ODP_QUEUE_INVALID;
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init_param;
	odp_pool_capability_t capa;
	odp_ipsec_config_t config;
	uint32_t max_seg_len;
	int num_workers;
	unsigned int i;
	odp_ipsec_sa_t sa;
	odp_shm_t shm;
	ipsec_alg_config_t *algs_config_base;
	unsigned int num_configs;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		app_err("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		app_err("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		app_err("ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		odp_shm_free(shm);
		exit(EXIT_FAILURE);
	}

	gbl_args_init(gbl_args);
	gbl_args->instance = instance;
	cargs = &gbl_args->cargs;

	/* Parse and store the application arguments */
	parse_args(argc, argv, cargs);
	num_workers = cargs->num_workers;

	/* Packet Pool Init */
	if (odp_pool_capability(&capa)) {
		app_err("Pool capability request failed.\n");
		exit(EXIT_FAILURE);
	}
	max_seg_len = capa.pkt.max_seg_len;

	for (i = 0; i < sizeof(global_payloads) / sizeof(unsigned int); i++) {
		if (global_payloads[i] > max_seg_len)
			break;
	}
	global_num_payloads = i;
	odp_pool_param_init(&param);
	param.pkt.seg_len = max_seg_len;
	param.pkt.len      = max_seg_len;
	param.pkt.num      = POOL_NUM_PKT;
	param.type         = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &param);

	if (pool == ODP_POOL_INVALID) {
		app_err("packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args->pkt_pool = pool;

	odp_pool_print(pool);

	/* Scheduler Init */
	if (odp_schedule_capability(&schedule_capa)) {
		printf("Error: Schedule capa failed.\n");
		return -1;
	}

	odp_schedule_config_init(&schedule_config);
	odp_schedule_config(&schedule_config);

	/* Input Queue init */
	odp_queue_param_init(&qparam);
	qparam.type = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync = cargs->sched_sync;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	qparam.sched.lock_count = schedule_capa.max_ordered_locks;

	in_queue = odp_queue_create("pktin", &qparam);

	odp_queue_print(in_queue);
	gbl_args->in_queue = in_queue;

	/* IPsec Config Init */
	odp_ipsec_config_init(&config);
	config.max_num_sa = 2;
	config.inbound.chksums.all_chksum = 0;
	config.outbound.all_chksum = 0;
	config.inbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config.outbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config.inbound.default_queue = ODP_QUEUE_INVALID;
	if (odp_ipsec_config(&config)) {
		app_err("odp_ipsec_config() failed\n");
		exit(EXIT_FAILURE);
	}

	odp_atomic_store_u32(&gbl_args->exit_threads, 0);

	cargs->num_workers = create_workers(num_workers);

	algs_config_base = algs_config;
	num_configs = NUM_CONFIGS;

	if (cargs->alg_config) {
		algs_config_base = cargs->alg_config;
		num_configs = 1;
	}

	for (i = 0; i < num_configs; i++) {
		ipsec_alg_config_t *alg_config;

		alg_config = algs_config_base + i;

		/* Create an SA for this Configuration */
		sa = create_sa_from_config(alg_config, cargs);
		if (sa == ODP_IPSEC_SA_INVALID) {
			printf("\n\tSA Creation Failed for [%s] Skipping test\n", alg_config->name);
			continue;
		}
		gbl_args->sa[0] = sa;

		print_result_header();

		/* Run tests for this SA */
		send_measure_one_config(cargs, alg_config);

		/* Delete the SA */
		odp_ipsec_sa_disable(sa);
		odp_ipsec_sa_destroy(sa);
	}

	/* Clean up */

	stop_workers();

	if (odp_pool_destroy(pool)) {
		app_err("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (ODP_QUEUE_INVALID != in_queue) {
		if (odp_queue_destroy(in_queue)) {
			app_err("Error: out_queue destroy failed.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		app_err("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		app_err("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
