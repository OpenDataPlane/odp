/* Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2022, Marvell
 * Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @example odp_ipsec.c
 *
 * Performance test application for IPsec APIs
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
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
#include <inttypes.h>

/** @def POOL_NUM_PKT
 * Number of packets in the pool
 */
#define POOL_NUM_PKT  4096

#define MAX_DEQUEUE_BURST 16

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

/**
 * Structure that holds template for sa create call
 * for different algorithms supported by test
 */
typedef struct {
	const char *name;		      /**< Algorithm name */
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
	int in_flight;

	/**
	 * Number of packets to be IPsec processed to get good average number.
	 * Specified through -c or --count option.
	 * Default is 10000.
	 */
	int packet_count;

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

	/**
	 * Use scheduler to get completion events from crypto operation.
	 * Specified through -s argument.
	 * */
	int schedule;

	/*
	 * Poll completion queue for crypto completion events.
	 * Specified through -p argument.
	 */
	int poll;

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

	/*
	 * Burst size.
	 * Prepare and submit as many packets for IPsec processing in each
	 * iteration of the loop.
	 */
	int burst_size;

	/*
	 * Use vector packet completion from IPsec APIs.
	 * Specified through -v or --vector argument.
	 */
	uint32_t vec_pkt_size;
} ipsec_args_t;

/*
 * Helper structure that holds averages for test of one algorithm
 * for given payload size.
 */
typedef struct {
	/**
	 * Elapsed time for one crypto operation.
	 */
	double elapsed;

	/**
	 * CPU time spent pre one crypto operation by whole process
	 * i.e include current and all other threads in process.
	 * It is filled with 'getrusage(RUSAGE_SELF, ...)' call.
	 */
	double rusage_self;

	/**
	 * CPU time spent per one crypto operation by current thread
	 * only. It is filled with 'getrusage(RUSAGE_THREAD, ...)'
	 * call.
	 */
	double rusage_thread;
} ipsec_run_result_t;

/**
 * Structure holds one snap to misc times of current process.
 */
typedef struct {
	struct timeval tv;	 /**< Elapsed time */
	struct rusage ru_self;	 /**< Rusage value for whole process */
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

/**
 * Find corresponding config for given name. Returns NULL
 * if config for given name is not found.
 */
static ipsec_alg_config_t *
find_config_by_name(const char *name)
{
	unsigned int i;
	ipsec_alg_config_t *ret = NULL;

	for (i = 0; i < ODPH_ARRAY_SIZE(algs_config); i++) {
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

	for (i = 0; i < ODPH_ARRAY_SIZE(algs_config); i++)
		printf("%s %s\n", prefix, algs_config[i].name);
}

/**
 * Snap current time values and put them into 'rec'.
 */
static void
fill_time_record(time_record_t *rec)
{
	gettimeofday(&rec->tv, NULL);
	getrusage(RUSAGE_SELF, &rec->ru_self);
	getrusage(RUSAGE_THREAD, &rec->ru_thread);
}

/**
 * Calculated CPU time difference for given two rusage structures.
 * Note it adds user space and system time together.
 */
static unsigned long long
get_rusage_diff(struct rusage *start, struct rusage *end)
{
	unsigned long long rusage_diff;
	unsigned long long rusage_start;
	unsigned long long rusage_end;

	rusage_start = (start->ru_utime.tv_sec * 1000000) +
		       (start->ru_utime.tv_usec);
	rusage_start += (start->ru_stime.tv_sec * 1000000) +
			(start->ru_stime.tv_usec);

	rusage_end = (end->ru_utime.tv_sec * 1000000) +
		     (end->ru_utime.tv_usec);
	rusage_end += (end->ru_stime.tv_sec * 1000000) +
		      (end->ru_stime.tv_usec);

	rusage_diff = rusage_end - rusage_start;

	return rusage_diff;
}

/**
 * Get diff for RUSAGE_SELF (whole process) between two time snap
 * records.
 */
static unsigned long long
get_rusage_self_diff(time_record_t *start, time_record_t *end)
{
	return get_rusage_diff(&start->ru_self, &end->ru_self);
}

/**
 * Get diff for RUSAGE_THREAD (current thread only) between two
 * time snap records.
 */
static unsigned long long
get_rusage_thread_diff(time_record_t *start, time_record_t *end)
{
	return get_rusage_diff(&start->ru_thread, &end->ru_thread);
}

/**
 * Get diff of elapsed time between two time snap records
 */
static unsigned long long
get_elapsed_usec(time_record_t *start, time_record_t *end)
{
	unsigned long long s;
	unsigned long long e;

	s = (start->tv.tv_sec * 1000000) + (start->tv.tv_usec);
	e = (end->tv.tv_sec * 1000000) + (end->tv.tv_usec);

	return e - s;
}

/**
 * Print header line for our report.
 */
static void
print_result_header(void)
{
	printf("\n%30.30s %15s %15s %15s %15s %15s %15s\n",
	       "algorithm", "avg over #", "payload (bytes)", "elapsed (us)",
	       "rusg self (us)", "rusg thrd (us)", "throughput (Kb)");
}

/**
 * Print one line of our report.
 */
static void
print_result(ipsec_args_t *cargs,
	     unsigned int payload_length,
	     ipsec_alg_config_t *config,
	     ipsec_run_result_t *result)
{
	unsigned int throughput;

	throughput = (1000000.0 / result->elapsed) * payload_length / 1024;
	printf("%30.30s %15d %15d %15.3f %15.3f %15.3f %15d\n",
	       config->name, cargs->packet_count, payload_length,
	       result->elapsed, result->rusage_self, result->rusage_thread,
	       throughput);
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
	odp_queue_t out_queue;

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

	if (cargs->schedule || cargs->poll) {
		out_queue = odp_queue_lookup("ipsec-out");
		if (out_queue == ODP_QUEUE_INVALID) {
			ODPH_ERR("ipsec-out queue not found\n");
			return ODP_IPSEC_SA_INVALID;
		}
		param.dest_queue = out_queue;
	} else {
		param.dest_queue = ODP_QUEUE_INVALID;
	}

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

static inline void debug_packets(int debug, odp_packet_t *pkt, int num_pkts)
{
	if (odp_likely(!debug))
		return;
	for (int i = 0; i < num_pkts; i++)
		odp_packet_print_data(pkt[i], 0, odp_packet_len(pkt[i]));
}

static int
make_packet_multi(odp_pool_t pkt_pool, unsigned int payload_length,
		  odp_packet_t pkt[], int num)
{
	int i, ret;

	ret = odp_packet_alloc_multi(pkt_pool, payload_length, pkt, num);
	if (ret != num) {
		ODPH_ERR("Could not allocate buffer\n");
		if (ret > 0)
			odp_packet_free_sp(pkt, ret);
		return -1;
	}

	for (i = 0; i < num; i++) {
		odp_packet_copy_from_mem(pkt[i], 0, sizeof(test_data), test_data);
		odp_packet_l3_offset_set(pkt[i], 0);

		uint8_t *mem = odp_packet_data(pkt[i]);
		((odph_ipv4hdr_t *)mem)->tot_len = odp_cpu_to_be_16(payload_length);
		memset(mem + sizeof(test_data), 1, payload_length - sizeof(test_data));
	}

	return 0;
}

static inline void check_ipsec_result(odp_packet_t ipsec_pkt)
{
	odp_ipsec_packet_result_t result;

	if (odp_unlikely(odp_ipsec_result(&result, ipsec_pkt)))
		ODPH_ERR("odp_ipsec_result() failed\n");
	else if (odp_unlikely(result.status.error.all))
		ODPH_ERR("IPsec processing error: %" PRIu32 "\n",
			 result.status.error.all);
}

/**
 * Run measurement iterations for given config and payload size.
 * Result of run returned in 'result' out parameter.
 */
static int
run_measure_one(ipsec_args_t *cargs,
		odp_ipsec_sa_t sa,
		unsigned int payload_length,
		time_record_t *start,
		time_record_t *end)
{
	int in_flight, pkts_allowed, num_out, num_pkts, rc = 0;
	const int max_in_flight = cargs->in_flight;
	const int burst_size = cargs->burst_size;
	const int packet_count = cargs->packet_count;
	const int debug = cargs->debug_packets;
	odp_ipsec_out_param_t param;
	odp_pool_t pkt_pool;

	pkt_pool = odp_pool_lookup("packet_pool");
	if (pkt_pool == ODP_POOL_INVALID) {
		ODPH_ERR("pkt_pool not found\n");
		return -1;
	}

	if (payload_length < sizeof(test_data))
		return -1;

	int packets_sent = 0;
	int packets_received = 0;

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));
	param.num_sa = 1;
	param.num_opt = 0;
	param.sa = &sa;

	fill_time_record(start);

	while ((packets_sent < packet_count) ||
	       (packets_received < packet_count)) {
		num_pkts = packet_count - packets_sent;

		/* Enqueue up to burst size */
		num_pkts = num_pkts > burst_size ? burst_size : num_pkts;

		/* Enqueue up to (max in flight - current in flight) */
		in_flight = packets_sent - packets_received;
		pkts_allowed = max_in_flight - in_flight;

		/* Enqueue either a burst of packets or skip */
		num_pkts = num_pkts > pkts_allowed ? 0 : num_pkts;

		if (odp_likely(num_pkts)) {
			odp_packet_t out_pkt[num_pkts];
			odp_packet_t pkt[num_pkts];
			int i;

			if (odp_unlikely(make_packet_multi(pkt_pool,
							   payload_length,
							   pkt,
							   num_pkts)))
				return -1;

			debug_packets(debug, pkt, num_pkts);
			num_out = num_pkts;

			rc = odp_ipsec_out(pkt, num_pkts,
					   out_pkt, &num_out,
					   &param);
			if (odp_unlikely(rc <= 0)) {
				ODPH_ERR("Failed odp_ipsec_out: rc = %d\n", rc);
				odp_packet_free_sp(pkt, num_pkts);
				break;
			}

			for (i = 0; i < num_out; i++)
				check_ipsec_result(out_pkt[i]);

			packets_sent += rc;
			packets_received += num_out;
			debug_packets(debug, out_pkt, num_out);

			if (odp_unlikely(rc != num_pkts))
				odp_packet_free_sp(&pkt[rc], num_pkts - rc);
			odp_packet_free_sp(out_pkt, num_out);
		}
	}

	fill_time_record(end);

	return rc < 0 ? rc : 0;
}

static uint32_t dequeue_burst(odp_queue_t polled_queue,
			      odp_event_t *events,
			      int max_burst)
{
	int num = 0;

	if (polled_queue != ODP_QUEUE_INVALID) {
		int rc = odp_queue_deq_multi(polled_queue,
					     events,
					     max_burst);
		num = odp_likely(rc >= 0) ? rc : 0;
	} else {
		num = odp_schedule_multi(NULL,
					 ODP_SCHED_NO_WAIT,
					 events,
					 max_burst);
	}
	return num;
}

static inline uint32_t vec_pkt_handle(int debug, odp_event_t ev)
{
	odp_packet_vector_t vec = odp_packet_vector_from_event(ev);
	uint32_t vec_size = odp_packet_vector_size(vec);
	odp_packet_t *pkt_tbl;
	uint32_t j;

	odp_packet_vector_tbl(vec, &pkt_tbl);

	for (j = 0; j < vec_size; j++)
		check_ipsec_result(pkt_tbl[j]);

	debug_packets(debug, pkt_tbl, vec_size);

	odp_packet_free_sp(pkt_tbl, vec_size);
	odp_packet_vector_free(vec);

	return vec_size;
}

static int
run_measure_one_async(ipsec_args_t *cargs,
		      odp_ipsec_sa_t sa,
		      unsigned int payload_length,
		      time_record_t *start,
		      time_record_t *end)
{
	int in_flight, packets_allowed, num_pkts, rc = 0;
	const int max_in_flight = cargs->in_flight;
	const int burst_size = cargs->burst_size;
	const int packet_count = cargs->packet_count;
	const int debug = cargs->debug_packets;
	odp_ipsec_out_param_t param;
	odp_pool_t pkt_pool;
	odp_queue_t polled_queue = ODP_QUEUE_INVALID;

	pkt_pool = odp_pool_lookup("packet_pool");
	if (pkt_pool == ODP_POOL_INVALID) {
		ODPH_ERR("pkt_pool not found\n");
		return -1;
	}

	if (cargs->poll) {
		polled_queue = odp_queue_lookup("ipsec-out");
		if (polled_queue == ODP_QUEUE_INVALID) {
			ODPH_ERR("ipsec-out queue not found\n");
			return -1;
		}
	}

	if (payload_length < sizeof(test_data))
		return -1;

	int packets_sent = 0;
	int packets_received = 0;

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));
	param.num_sa = 1;
	param.num_opt = 0;
	param.sa = &sa;

	fill_time_record(start);

	while ((packets_sent < packet_count) ||
	       (packets_received < packet_count)) {

		num_pkts = packet_count - packets_sent;

		/* Enqueue up to burst size */
		num_pkts = num_pkts > burst_size ? burst_size : num_pkts;

		/* Enqueue up to (max in flight - current in flight) */
		in_flight = packets_sent - packets_received;
		packets_allowed = max_in_flight - in_flight;

		if (num_pkts > 0 && num_pkts <= packets_allowed) {
			odp_packet_t pkt[num_pkts];

			if (odp_unlikely(make_packet_multi(pkt_pool,
							   payload_length,
							   pkt,
							   num_pkts)))
				return -1;

			debug_packets(debug, pkt, num_pkts);

			rc = odp_ipsec_out_enq(pkt, num_pkts, &param);
			if (odp_unlikely(rc <= 0)) {
				ODPH_ERR("Failed odp_ipsec_out_enq: rc = %d\n",
					 rc);
				odp_packet_free_sp(pkt, num_pkts);
				break;
			}

			if (odp_unlikely(rc != num_pkts))
				odp_packet_free_sp(&pkt[rc], num_pkts - rc);

			packets_sent += rc;
		} else {
			odp_packet_t pkt_out[max_in_flight];
			int i = 0;

			/*
			 * Dequeue packets until we can enqueue the next burst
			 * or until we have received all remaining packets
			 * when there are no more packets to be sent.
			 */
			while (num_pkts > packets_allowed ||
			       (num_pkts == 0 && packets_received < packet_count)) {
				odp_event_t events[MAX_DEQUEUE_BURST];
				uint32_t num;

				num = dequeue_burst(polled_queue, events, MAX_DEQUEUE_BURST);

				for (uint32_t n = 0; n < num; n++) {
					if (odp_event_type(events[n]) == ODP_EVENT_PACKET_VECTOR) {
						uint32_t vec_size;

						vec_size = vec_pkt_handle(debug, events[n]);
						packets_received += vec_size - 1;
						packets_allowed += vec_size - 1;
					} else {
						pkt_out[i] = odp_ipsec_packet_from_event(events[n]);
						check_ipsec_result(pkt_out[i]);
						i++;
					}

				}
				packets_received += num;
				packets_allowed += num;
			}
			debug_packets(debug, pkt_out, i);

			if (i > 0)
				odp_packet_free_sp(pkt_out, i);
		}
	}

	fill_time_record(end);

	return rc < 0 ? rc : 0;
}

/**
 * Process one algorithm. Note if paload size is specicified it is
 * only one run. Or iterate over set of predefined payloads.
 */
static int
run_measure_one_config(ipsec_args_t *cargs,
		       ipsec_alg_config_t *config)
{
	unsigned int num_payloads = global_num_payloads;
	unsigned int *payloads = global_payloads;
	odp_ipsec_capability_t capa;
	odp_ipsec_sa_t sa;
	unsigned int i;
	int rc = 0;

	if (odp_ipsec_capability(&capa) < 0) {
		ODPH_ERR("IPSEC capability call failed.\n");
		return -1;
	}

	if (cargs->ah && (ODP_SUPPORT_NO == capa.proto_ah)) {
		ODPH_ERR("IPSEC AH protocol not supported.\n");
		return -1;
	}

	rc = odph_ipsec_alg_check(&capa, config->crypto.cipher_alg,
				  config->crypto.cipher_key.length,
				  config->crypto.auth_alg,
				  config->crypto.auth_key.length);

	if (rc) {
		printf("    => %s skipped\n\n", config->name);
		return 0;
	}

	sa = create_sa_from_config(config, cargs);
	if (sa == ODP_IPSEC_SA_INVALID) {
		ODPH_ERR("IPsec SA create failed.\n");
		return -1;
	}

	print_result_header();
	if (cargs->payload_length) {
		num_payloads = 1;
		payloads = &cargs->payload_length;
	}

	for (i = 0; i < num_payloads; i++) {
		double count;
		ipsec_run_result_t result;
		time_record_t start, end;

		if (cargs->schedule || cargs->poll)
			rc = run_measure_one_async(cargs, sa,
						   payloads[i],
						   &start, &end);
		else
			rc = run_measure_one(cargs, sa,
					     payloads[i],
					     &start, &end);
		if (rc)
			break;

		count = get_elapsed_usec(&start, &end);
		result.elapsed = count / cargs->packet_count;

		count = get_rusage_self_diff(&start, &end);
		result.rusage_self = count / cargs->packet_count;

		count = get_rusage_thread_diff(&start, &end);
		result.rusage_thread = count / cargs->packet_count;

		print_result(cargs, payloads[i],
			     config, &result);
	}

	odp_ipsec_sa_disable(sa);
	if (cargs->schedule || cargs->poll) {
		odp_queue_t out_queue = odp_queue_lookup("ipsec-out");
		odp_ipsec_status_t status;

		while (1) {
			odp_event_t event;

			if (cargs->poll)
				event = odp_queue_deq(out_queue);
			else
				event = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

			if (event != ODP_EVENT_INVALID &&
			    odp_event_type(event) == ODP_EVENT_IPSEC_STATUS &&
			    odp_ipsec_status(&status, event) == ODP_IPSEC_OK &&
			    status.id == ODP_IPSEC_STATUS_SA_DISABLE &&
			    status.sa == sa)
				break;
		}
	}
	odp_ipsec_sa_destroy(sa);

	return rc;
}

typedef struct thr_arg {
	ipsec_args_t ipsec_args;
	ipsec_alg_config_t *ipsec_alg_config;
} thr_arg_t;

static int run_thr_func(void *arg)
{
	thr_arg_t *thr_args = (thr_arg_t *)arg;

	run_measure_one_config(&thr_args->ipsec_args,
			       thr_args->ipsec_alg_config);
	return 0;
}

/**
 * Print usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i 100000\n"
	       "\n"
	       "OpenDataPlane crypto speed measure.\n"
	       "Optional OPTIONS\n"
	       "  -a, --algorithm <name> Specify algorithm name (default all)\n"
	       "			 Supported values are:\n",
	       progname, progname);

	print_config_names("				      ");
	printf("  -d, --debug	       Enable dump of processed packets.\n"
	       "  -f, --flight <number> Max number of packet processed in parallel (default 1)\n"
	       "  -c, --count <number> Number of packets (default 10000)\n"
	       "  -b, --burst <number> Number of packets in one IPsec API submission (default 1)\n"
	       "  -v, --vector <number> Enable vector packet completion from IPsec APIs with specified vector size.\n"
	       "  -l, --payload	       Payload length.\n"
	       "  -s, --schedule       Use scheduler for completion events.\n"
	       "  -p, --poll           Poll completion queue for completion events.\n"
	       "  -t, --tunnel         Use tunnel-mode IPsec transformation.\n"
	       "  -u, --ah             Use AH transformation instead of ESP.\n"
	       "  -h, --help	       Display help and exit.\n"
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
		{"count", optional_argument, NULL, 'c'},
		{"burst", optional_argument, NULL, 'b'},
		{"vector", optional_argument, NULL, 'v'},
		{"payload", optional_argument, NULL, 'l'},
		{"sessions", optional_argument, NULL, 'm'},
		{"poll", no_argument, NULL, 'p'},
		{"schedule", no_argument, NULL, 's'},
		{"tunnel", no_argument, NULL, 't'},
		{"ah", no_argument, NULL, 'u'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:b:c:df:hm:nl:sptuv:";

	cargs->in_flight = 1;
	cargs->debug_packets = 0;
	cargs->packet_count = 10000;
	cargs->burst_size = 1;
	cargs->vec_pkt_size = 0;
	cargs->payload_length = 0;
	cargs->alg_config = NULL;
	cargs->schedule = 0;
	cargs->ah = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'a':
			cargs->alg_config = find_config_by_name(optarg);
			if (!cargs->alg_config) {
				printf("cannot test crypto '%s' configuration\n",
				       optarg);
				usage(argv[0]);
				exit(-1);
			}
			break;
		case 'd':
			cargs->debug_packets = 1;
			break;
		case 'c':
			cargs->packet_count = atoi(optarg);
			break;
		case 'b':
			if (optarg == NULL)
				cargs->burst_size = 32;
			else
				cargs->burst_size = atoi(optarg);
			if (cargs->burst_size > POOL_NUM_PKT) {
				printf("Invalid burst size (max allowed: %d)\n", POOL_NUM_PKT);
				exit(-1);
			}
			break;
		case 'v':
			if (optarg == NULL)
				cargs->vec_pkt_size = 32;
			else
				cargs->vec_pkt_size = atoi(optarg);
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
		case 's':
			cargs->schedule = 1;
			break;
		case 'p':
			cargs->poll = 1;
			break;
		case 't':
			cargs->tunnel = 1;
			break;
		case 'u':
			cargs->ah = 1;
			break;
		default:
			break;
		}
	}

	if (cargs->in_flight < cargs->burst_size) {
		printf("-f (flight) must be greater than or equal to -b (burst)\n");
		exit(-1);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */

	if (cargs->schedule && cargs->poll) {
		printf("-s (schedule) and -p (poll) options are not compatible\n");
		usage(argv[0]);
		exit(-1);
	}
}

int main(int argc, char *argv[])
{
	odp_pool_t vec_pool = ODP_POOL_INVALID;
	ipsec_args_t cargs;
	odp_pool_t pool;
	odp_queue_param_t qparam;
	odp_pool_param_t param;
	odp_queue_t out_queue = ODP_QUEUE_INVALID;
	thr_arg_t thr_arg;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	int num_workers = 1;
	odph_helper_options_t helper_options;
	odph_thread_t thread_tbl[num_workers];
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_instance_t instance;
	odp_init_t init_param;
	odp_ipsec_capability_t ipsec_capa;
	odp_pool_capability_t capa;
	odp_ipsec_config_t config;
	uint32_t max_seg_len;
	unsigned int i;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	memset(&cargs, 0, sizeof(cargs));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &cargs);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	if (odp_pool_capability(&capa)) {
		ODPH_ERR("Pool capability request failed.\n");
		exit(EXIT_FAILURE);
	}

	max_seg_len = capa.pkt.max_seg_len;

	for (i = 0; i < ODPH_ARRAY_SIZE(global_payloads); i++) {
		if (global_payloads[i] > max_seg_len)
			break;
	}

	global_num_payloads = i;

	/* Create packet pool */
	odp_pool_param_init(&param);
	param.pkt.seg_len = max_seg_len;
	param.pkt.len	   = max_seg_len;
	param.pkt.num	   = POOL_NUM_PKT;
	param.type	   = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	if (odp_ipsec_capability(&ipsec_capa) < 0) {
		ODPH_ERR("IPSEC capability call failed.\n");
		exit(EXIT_FAILURE);
	}

	if (cargs.schedule && !ipsec_capa.queue_type_sched) {
		ODPH_ERR("Scheduled type destination queue not supported.\n");
		exit(EXIT_FAILURE);
	}

	if (cargs.poll && !ipsec_capa.queue_type_plain) {
		ODPH_ERR("Plain type destination queue not supported.\n");
		exit(EXIT_FAILURE);
	}

	if (cargs.vec_pkt_size) {
		if (capa.vector.max_pools < 1) {
			ODPH_ERR("Vector packet pool not available");
			exit(EXIT_FAILURE);
		}

		if (!ipsec_capa.vector.supported) {
			ODPH_ERR("Vector packet completion not supported by IPsec.\n");
			exit(EXIT_FAILURE);
		}

		if (capa.vector.max_size < cargs.vec_pkt_size) {
			ODPH_ERR("Vector size larger than max size supported by vector pool.\n");
			exit(EXIT_FAILURE);
		}

		if (!cargs.schedule && !cargs.poll) {
			ODPH_ERR("Vector packet is not supported with sync APIs.\n");
			exit(EXIT_FAILURE);
		}

		/* Create vector pool */
		odp_pool_param_init(&param);
		param.vector.num	= POOL_NUM_PKT;
		param.vector.max_size	= cargs.vec_pkt_size;
		param.type		= ODP_POOL_VECTOR;
		vec_pool = odp_pool_create("vector_pool", &param);

		if (vec_pool == ODP_POOL_INVALID) {
			ODPH_ERR("Vector packet pool create failed.\n");
			exit(EXIT_FAILURE);
		}

		odp_pool_print(vec_pool);
	}

	odp_ipsec_config_init(&config);
	config.max_num_sa = 2;
	config.inbound.chksums.all_chksum = 0;
	config.outbound.all_chksum = 0;

	if (vec_pool != ODP_POOL_INVALID) {
		config.vector.enable = true;
		config.vector.pool = vec_pool;
		config.vector.max_size = cargs.vec_pkt_size;
		config.vector.max_tmo_ns = ipsec_capa.vector.max_tmo_ns;
	}

	odp_queue_param_init(&qparam);
	if (cargs.schedule) {
		odp_schedule_config(NULL);
		qparam.type = ODP_QUEUE_TYPE_SCHED;
		qparam.sched.prio  = odp_schedule_default_prio();
		qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;
		out_queue = odp_queue_create("ipsec-out", &qparam);
	} else if (cargs.poll) {
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		out_queue = odp_queue_create("ipsec-out", &qparam);
	}
	if (cargs.schedule || cargs.poll) {
		if (out_queue == ODP_QUEUE_INVALID) {
			ODPH_ERR("ipsec-out queue create failed.\n");
			exit(EXIT_FAILURE);
		}
		config.inbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
		config.outbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
		config.inbound.default_queue = out_queue;
	} else {
		config.inbound_mode = ODP_IPSEC_OP_MODE_SYNC;
		config.outbound_mode = ODP_IPSEC_OP_MODE_SYNC;
		config.inbound.default_queue = ODP_QUEUE_INVALID;
	}
	if (odp_ipsec_config(&config)) {
		ODPH_ERR("odp_ipsec_config() failed\n");
		exit(EXIT_FAILURE);
	}

	if (cargs.schedule) {
		printf("Run in async scheduled mode\n");

		thr_arg.ipsec_args = cargs;
		thr_arg.ipsec_alg_config = cargs.alg_config;
		num_workers = odp_cpumask_default_worker(&cpumask,
							 num_workers);
		(void)odp_cpumask_to_str(&cpumask, cpumaskstr,
					 sizeof(cpumaskstr));
		printf("num worker threads:  %i\n",
		       num_workers);
		printf("first CPU:	     %i\n",
		       odp_cpumask_first(&cpumask));
		printf("cpu mask:	     %s\n",
		       cpumaskstr);
	} else if (cargs.poll) {
		printf("Run in async poll mode\n");
	} else {
		printf("Run in sync mode\n");
	}

	if (cargs.alg_config) {
		odph_thread_common_param_init(&thr_common);
		thr_common.instance = instance;
		thr_common.cpumask = &cpumask;
		thr_common.share_param = 1;

		if (cargs.schedule) {
			odph_thread_param_init(&thr_param);
			thr_param.start = run_thr_func;
			thr_param.arg = &thr_arg;
			thr_param.thr_type = ODP_THREAD_WORKER;

			memset(thread_tbl, 0, sizeof(thread_tbl));
			odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers);

			odph_thread_join(thread_tbl, num_workers);
		} else {
			run_measure_one_config(&cargs, cargs.alg_config);
		}
	} else {
		for (i = 0; i < ODPH_ARRAY_SIZE(algs_config); i++) {
			if (cargs.ah &&
			    algs_config[i].crypto.cipher_alg !=
			    ODP_CIPHER_ALG_NULL)
				continue;
			run_measure_one_config(&cargs, algs_config + i);
		}
	}

	if (cargs.schedule || cargs.poll)
		odp_queue_destroy(out_queue);

	if (cargs.vec_pkt_size) {
		if (odp_pool_destroy(vec_pool)) {
			ODPH_ERR("Error: vector pool destroy\n");
			exit(EXIT_FAILURE);
		}
	}

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Error: pool destroy\n");
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

	return 0;
}

