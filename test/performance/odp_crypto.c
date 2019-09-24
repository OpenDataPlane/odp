/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
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
#define POOL_NUM_PKT  64

static uint8_t test_iv[16] = "0123456789abcdef";

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
 * Structure that holds template for session create call
 * for different algorithms supported by test
 */
typedef struct {
	const char *name;		      /**< Algorithm name */
	odp_crypto_session_param_t session;   /**< Prefilled crypto session params */
} crypto_alg_config_t;

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
	 * If non zero Try to run crypto operation in place. Note some
	 * implementation may not support such mode. Enabled by -n or
	 * --inplace option.
	 */
	int in_place;

	/**
	 * If non zeor output of previous operation taken as input for
	 * next encrypt operations. Enabled by -r or --reuse option.
	 */
	int reuse_packet;

	/**
	 * Maximum number of outstanding encryption requests. Note code
	 * poll for results over queue and if nothing is available it can
	 * submit more encryption requests up to maximum number specified by
	 * this option. Specified through -f or --flight option.
	 */
	int in_flight;

	/**
	 * Number of iteration to repeat crypto operation to get good
	 * average number. Specified through -i or --terations option.
	 * Default is 10000.
	 */
	int iteration_count;

	/**
	 * Maximum sessions. Currently is not used.
	 */
	int max_sessions;

	/**
	 * Payload size to test. If 0 set of predefined payload sizes
	 * is tested. Specified through -p or --payload option.
	 */
	int payload_length;

	/**
	 * Pointer to selected algorithm to test. If NULL all available
	 * alogorthims are tested. Name of algorithm is passed through
	 * -a or --algorithm option.
	 */
	crypto_alg_config_t *alg_config;

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
} crypto_args_t;

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
} crypto_run_result_t;

/**
 * Structure holds one snap to misc times of current process.
 */
typedef struct {
	struct timeval tv;	 /**< Elapsed time */
	struct rusage ru_self;	 /**< Rusage value for whole process */
	struct rusage ru_thread; /**< Rusage value for current thread */
} time_record_t;

/* Arguments for one test run */
typedef struct test_run_arg_t {
	crypto_args_t crypto_args;
	crypto_alg_config_t *crypto_alg_config;
	odp_crypto_capability_t crypto_capa;

} test_run_arg_t;

static void parse_args(int argc, char *argv[], crypto_args_t *cargs);
static void usage(char *progname);

/**
 * Set of predefined payloads.
 */
static unsigned int payloads[] = {
	16,
	64,
	256,
	1024,
	8192,
	16384
};

/** Number of payloads used in the test */
static unsigned num_payloads;

/**
 * Set of known algorithms to test
 */
static crypto_alg_config_t algs_config[] = {
	{
		.name = "3des-cbc-null",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_3DES_CBC,
			.cipher_key = {
				.data = test_key24,
				.length = sizeof(test_key24)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 8,
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},
	{
		.name = "3des-cbc-hmac-md5-96",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_3DES_CBC,
			.cipher_key = {
				.data = test_key24,
				.length = sizeof(test_key24)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 8,
			},
			.auth_alg = ODP_AUTH_ALG_MD5_HMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_digest_len = 12,
		},
	},
	{
		.name = "null-hmac-md5-96",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_MD5_HMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_digest_len = 12,
		},
	},
	{
		.name = "aes-cbc-null",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CBC,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 16,
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},
	{
		.name = "aes-cbc-hmac-sha1-96",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CBC,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 16,
			},
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
			.auth_digest_len = 12,
		},
	},
	{
		.name = "null-hmac-sha1-96",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
			.auth_digest_len = 12,
		},
	},
	{
		.name = "aes-ctr-null",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CTR,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 16,
			},
			.auth_alg = ODP_AUTH_ALG_NULL
		},
	},
	{
		.name = "aes-ctr-hmac-sha1-96",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CTR,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 16,
			},
			.auth_alg = ODP_AUTH_ALG_SHA1_HMAC,
			.auth_key = {
				.data = test_key20,
				.length = sizeof(test_key20)
			},
			.auth_digest_len = 12,
		},
	},
	{
		.name = "null-hmac-sha256-128",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA256_HMAC,
			.auth_key = {
				.data = test_key32,
				.length = sizeof(test_key32)
			},
			.auth_digest_len = 16,
		},
	},
	{
		.name = "null-hmac-sha512-256",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_SHA512_HMAC,
			.auth_key = {
				.data = test_key64,
				.length = sizeof(test_key64)
			},
			.auth_digest_len = 32,
		},
	},
	{
		.name = "null-aes-gmac",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_NULL,
			.auth_alg = ODP_AUTH_ALG_AES_GMAC,
			.auth_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.auth_iv = {
				.data = test_iv,
				.length = 12,
			},
			.auth_digest_len = 16,
		},
	},
	{
		.name = "aes-gcm",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_GCM,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 12,
			},
			.auth_alg = ODP_AUTH_ALG_AES_GCM,
			.auth_digest_len = 16,
		},
	},
	{
		.name = "aes-ccm",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_AES_CCM,
			.cipher_key = {
				.data = test_key16,
				.length = sizeof(test_key16)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 11,
			},
			.auth_alg = ODP_AUTH_ALG_AES_CCM,
			.auth_digest_len = 16,
		},
	},
	{
		.name = "chacha20-poly1305",
		.session = {
			.cipher_alg = ODP_CIPHER_ALG_CHACHA20_POLY1305,
			.cipher_key = {
				.data = test_key32,
				.length = sizeof(test_key32)
			},
			.cipher_iv = {
				.data = test_iv,
				.length = 12,
			},
			.auth_alg = ODP_AUTH_ALG_CHACHA20_POLY1305,
			.auth_digest_len = 16,
		},
	},
};

/**
 * Find corresponding config for given name. Returns NULL
 * if config for given name is not found.
 */
static crypto_alg_config_t *
find_config_by_name(const char *name) {
	unsigned int i;
	crypto_alg_config_t *ret = NULL;

	for (i = 0; i < (sizeof(algs_config) / sizeof(crypto_alg_config_t));
	     i++) {
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
print_config_names(const char *prefix) {
	unsigned int i;

	for (i = 0; i < (sizeof(algs_config) / sizeof(crypto_alg_config_t));
	     i++) {
		printf("%s %s\n", prefix, algs_config[i].name);
	}
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

	s = (start->tv.tv_sec * 1000000) +
	    (start->tv.tv_usec);
	e = (end->tv.tv_sec * 1000000) +
	    (end->tv.tv_usec);

	return e - s;
}

#define REPORT_HEADER	    "\n%30.30s %15s %15s %15s %15s %15s %15s\n"
#define REPORT_LINE	    "%30.30s %15d %15d %15.3f %15.3f %15.3f %15d\n"

/**
 * Print header line for our report.
 */
static void
print_result_header(void)
{
	printf(REPORT_HEADER,
	       "algorithm", "avg over #", "payload (bytes)", "elapsed (us)",
	       "rusg self (us)", "rusg thrd (us)", "throughput (Kb)");
}

/**
 * Print one line of our report.
 */
static void
print_result(crypto_args_t *cargs,
	     unsigned int payload_length,
	     crypto_alg_config_t *config,
	     crypto_run_result_t *result)
{
	unsigned int throughput;

	throughput = (1000000.0 / result->elapsed) * payload_length / 1024;
	printf(REPORT_LINE,
	       config->name, cargs->iteration_count, payload_length,
	       result->elapsed, result->rusage_self, result->rusage_thread,
	       throughput);
}

/**
 * Print piece of memory with given size.
 */
static void
print_mem(const char *msg,
	  const unsigned char *ptr,
	  unsigned int len)
{
	unsigned i, j;
	char c;
	char line[81];
	char *p;

	if (msg)
		printf("\n%s (bytes size = %d)", msg, len);

	for (i = 0; i < len; i += 16) {
		p = line;
		sprintf(p, "\n%04x   ", i); p += 8;

		for (j = 0; j < 16; j++) {
			if (i + j == len)
				break;

			sprintf(p, " %02x", (ptr)[i + j]); p += 3;
		}

		for (; j < 16; j++) {
			sprintf(p, "   "); p += 3;
		}

		sprintf(p, "   "); p += 3;

		for (j = 0; j < 16; j++) {
			if (i + j == len)
				break;
			c = (ptr)[i + j];
			*p++ = (' ' <= c && c <= '~') ? c : '.';
		}

		*p = '\0';
		printf("%s", line);
	}
	printf("\n");
}

/**
 * Create ODP crypto session for given config.
 */
static int
create_session_from_config(odp_crypto_session_t *session,
			   crypto_alg_config_t *config,
			   crypto_args_t *cargs)
{
	odp_crypto_session_param_t params;
	odp_crypto_ses_create_err_t ses_create_rc;
	odp_pool_t pkt_pool;
	odp_queue_t out_queue;

	odp_crypto_session_param_init(&params);
	memcpy(&params, &config->session, sizeof(odp_crypto_session_param_t));
	params.op = ODP_CRYPTO_OP_ENCODE;
	params.pref_mode   = ODP_CRYPTO_SYNC;

	/* Lookup the packet pool */
	pkt_pool = odp_pool_lookup("packet_pool");
	if (pkt_pool == ODP_POOL_INVALID) {
		app_err("packet_pool pool not found\n");
		return -1;
	}
	params.output_pool = pkt_pool;

	if (cargs->schedule || cargs->poll) {
		out_queue = odp_queue_lookup("crypto-out");
		if (out_queue == ODP_QUEUE_INVALID) {
			app_err("crypto-out queue not found\n");
			return -1;
		}
		params.compl_queue = out_queue;
		params.op_mode = ODP_CRYPTO_ASYNC;
	} else {
		params.compl_queue = ODP_QUEUE_INVALID;
		params.op_mode = ODP_CRYPTO_SYNC;
	}
	if (odp_crypto_session_create(&params, session,
				      &ses_create_rc)) {
		app_err("crypto session create failed.\n");
		return -1;
	}

	return 0;
}

static odp_packet_t
make_packet(odp_pool_t pkt_pool, unsigned int payload_length)
{
	odp_packet_t pkt;

	pkt = odp_packet_alloc(pkt_pool, payload_length);
	if (pkt == ODP_PACKET_INVALID) {
		app_err("failed to allocate buffer\n");
		return pkt;
	}

	void *mem = odp_packet_data(pkt);

	memset(mem, 1, payload_length);

	return pkt;
}

/**
 * Run measurement iterations for given config and payload size.
 * Result of run returned in 'result' out parameter.
 */
static int
run_measure_one(crypto_args_t *cargs,
		crypto_alg_config_t *config,
		odp_crypto_session_t *session,
		unsigned int payload_length,
		crypto_run_result_t *result)
{
	odp_crypto_packet_op_param_t params;

	odp_pool_t pkt_pool;
	odp_queue_t out_queue;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	int rc = 0;

	pkt_pool = odp_pool_lookup("packet_pool");
	if (pkt_pool == ODP_POOL_INVALID) {
		app_err("pkt_pool not found\n");
		return -1;
	}

	out_queue = odp_queue_lookup("crypto-out");
	if (cargs->schedule || cargs->poll) {
		if (out_queue == ODP_QUEUE_INVALID) {
			app_err("crypto-out queue not found\n");
			return -1;
		}
	}

	if (cargs->reuse_packet) {
		pkt = make_packet(pkt_pool, payload_length);
		if (ODP_PACKET_INVALID == pkt)
			return -1;
	}

	time_record_t start, end;
	int packets_sent = 0;
	int packets_received = 0;

	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = *session;

	params.cipher_range.offset = 0;
	params.cipher_range.length = payload_length;

	params.auth_range.offset = 0;
	params.auth_range.length = payload_length;
	params.hash_result_offset = payload_length;

	fill_time_record(&start);

	while ((packets_sent < cargs->iteration_count) ||
	       (packets_received <  cargs->iteration_count)) {
		void *mem;

		if ((packets_sent < cargs->iteration_count) &&
		    (packets_sent - packets_received <
		     cargs->in_flight)) {
			odp_packet_t out_pkt;

			if (!cargs->reuse_packet) {
				pkt = make_packet(pkt_pool, payload_length);
				if (ODP_PACKET_INVALID == pkt)
					return -1;
			}

			out_pkt = cargs->in_place ? pkt : ODP_PACKET_INVALID;

			if (cargs->debug_packets) {
				mem = odp_packet_data(pkt);
				print_mem("Packet before encryption:",
					  mem, payload_length);
			}

			if (cargs->schedule || cargs->poll) {
				rc = odp_crypto_op_enq(&pkt, &out_pkt,
						       &params, 1);
				if (rc <= 0) {
					app_err("failed odp_crypto_packet_op_enq: rc = %d\n",
						rc);
					if (!cargs->reuse_packet)
						odp_packet_free(pkt);
					break;
				}
				packets_sent += rc;
			} else {
				rc = odp_crypto_op(&pkt, &out_pkt,
						   &params, 1);
				if (rc <= 0) {
					app_err("failed odp_crypto_packet_op: rc = %d\n",
						rc);
					if (!cargs->reuse_packet)
						odp_packet_free(pkt);
					break;
				}
				packets_sent += rc;
				packets_received++;
				if (cargs->debug_packets) {
					mem = odp_packet_data(out_pkt);
					print_mem("Immediately encrypted "
						   "packet",
						  mem,
						  payload_length +
						  config->session.
						   auth_digest_len);
				}
				if (cargs->reuse_packet)
					pkt = out_pkt;
				else
					odp_packet_free(out_pkt);
			}
		}

		if (cargs->schedule || cargs->poll) {
			odp_event_t ev;
			odp_crypto_packet_result_t result;
			odp_packet_t out_pkt;

			if (cargs->schedule)
				ev = odp_schedule(NULL,
						  ODP_SCHED_NO_WAIT);
			else
				ev = odp_queue_deq(out_queue);

			while (ev != ODP_EVENT_INVALID) {
				out_pkt = odp_crypto_packet_from_event(ev);
				odp_crypto_result(&result, out_pkt);

				if (cargs->debug_packets) {
					mem = odp_packet_data(out_pkt);
					print_mem("Received encrypted packet",
						  mem,
						  payload_length +
						  config->
						  session.auth_digest_len);
				}
				if (cargs->reuse_packet)
					pkt = out_pkt;
				else
					odp_packet_free(out_pkt);
				packets_received++;
				if (cargs->schedule)
					ev = odp_schedule(NULL,
							  ODP_SCHED_NO_WAIT);
				else
					ev = odp_queue_deq(out_queue);
			};
		}
	}

	fill_time_record(&end);

	{
		double count;

		count = get_elapsed_usec(&start, &end);
		result->elapsed = count /
				  cargs->iteration_count;

		count = get_rusage_self_diff(&start, &end);
		result->rusage_self = count /
				      cargs->iteration_count;

		count = get_rusage_thread_diff(&start, &end);
		result->rusage_thread = count /
					cargs->iteration_count;
	}

	if (cargs->reuse_packet)
		odp_packet_free(pkt);

	return rc < 0 ? rc : 0;
}

static int check_cipher_alg(odp_crypto_capability_t *capa,
			    odp_cipher_alg_t alg)
{
	switch (alg) {
	case ODP_CIPHER_ALG_NULL:
		if (capa->ciphers.bit.null)
			return 0;
		break;
	case ODP_CIPHER_ALG_DES:
		if (capa->ciphers.bit.des)
			return 0;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (capa->ciphers.bit.trides_cbc)
			return 0;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (capa->ciphers.bit.aes_cbc)
			return 0;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		if (capa->ciphers.bit.aes_ctr)
			return 0;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (capa->ciphers.bit.aes_gcm)
			return 0;
		break;
	case ODP_CIPHER_ALG_AES_CCM:
		if (capa->ciphers.bit.aes_ccm)
			return 0;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		if (capa->ciphers.bit.chacha20_poly1305)
			return 0;
		break;
	default:
		break;
	}

	return -1;
}

static int check_auth_alg(odp_crypto_capability_t *capa,
			  odp_auth_alg_t alg)
{
	switch (alg) {
	case ODP_AUTH_ALG_NULL:
		if (capa->auths.bit.null)
			return 0;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (capa->auths.bit.md5_hmac)
			return 0;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (capa->auths.bit.sha1_hmac)
			return 0;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (capa->auths.bit.sha256_hmac)
			return 0;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		if (capa->auths.bit.sha384_hmac)
			return 0;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (capa->auths.bit.sha512_hmac)
			return 0;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (capa->auths.bit.aes_gcm)
			return 0;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (capa->auths.bit.aes_gmac)
			return 0;
		break;
	case ODP_AUTH_ALG_AES_CCM:
		if (capa->auths.bit.aes_ccm)
			return 0;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		if (capa->auths.bit.chacha20_poly1305)
			return 0;
		break;
	default:
		break;
	}

	return -1;
}

/**
 * Process one algorithm. Note if paload size is specicified it is
 * only one run. Or iterate over set of predefined payloads.
 */
static int run_measure_one_config(test_run_arg_t *arg)
{
	crypto_run_result_t result;
	odp_crypto_session_t session;
	crypto_args_t *cargs = &arg->crypto_args;
	crypto_alg_config_t *config = arg->crypto_alg_config;
	odp_crypto_capability_t crypto_capa = arg->crypto_capa;
	int rc = 0;

	if (check_cipher_alg(&crypto_capa, config->session.cipher_alg)) {
		printf("    Cipher algorithm not supported\n");
		rc = 1;
	}

	if (check_auth_alg(&crypto_capa, config->session.auth_alg)) {
		printf("    Auth algorithm not supported\n");
		rc = 1;
	}

	if (rc) {
		printf("    => %s skipped\n\n", config->name);
		return 0;
	}

	if (create_session_from_config(&session, config, cargs))
		return -1;

	if (cargs->payload_length) {
		rc = run_measure_one(cargs, config, &session,
				     cargs->payload_length, &result);
		if (!rc) {
			print_result_header();
			print_result(cargs, cargs->payload_length,
				     config, &result);
		}
	} else {
		unsigned i;

		print_result_header();
		for (i = 0; i < num_payloads; i++) {
			rc = run_measure_one(cargs, config, &session,
					     payloads[i], &result);
			if (rc)
				break;
			print_result(cargs, payloads[i],
				     config, &result);
		}
	}

	odp_crypto_session_destroy(session);

	return rc;
}

static int run_thr_func(void *arg)
{
	run_measure_one_config((test_run_arg_t *)arg);
	return 0;
}

int main(int argc, char *argv[])
{
	crypto_args_t cargs;
	odp_pool_t pool;
	odp_queue_param_t qparam;
	odp_pool_param_t params;
	odp_queue_t out_queue = ODP_QUEUE_INVALID;
	test_run_arg_t test_run_arg;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	int num_workers = 1;
	odph_helper_options_t helper_options;
	odph_odpthread_t thr[num_workers];
	odp_instance_t instance;
	odp_init_t init_param;
	odp_pool_capability_t pool_capa;
	odp_crypto_capability_t crypto_capa;
	uint32_t max_seg_len;
	unsigned i;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		app_err("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	memset(&cargs, 0, sizeof(cargs));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &cargs);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		app_err("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	odp_init_local(instance, ODP_THREAD_WORKER);

	if (odp_crypto_capability(&crypto_capa)) {
		app_err("Crypto capability request failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_capability(&pool_capa)) {
		app_err("Pool capability request failed.\n");
		exit(EXIT_FAILURE);
	}

	max_seg_len = pool_capa.pkt.max_seg_len;

	for (i = 0; i < sizeof(payloads) / sizeof(unsigned int); i++) {
		if (payloads[i] > max_seg_len)
			break;
	}

	num_payloads = i;

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = max_seg_len;
	params.pkt.len	   = max_seg_len;
	params.pkt.num	   = POOL_NUM_PKT;
	params.type	   = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		app_err("packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	odp_queue_param_init(&qparam);
	if (cargs.schedule) {
		odp_schedule_config(NULL);
		qparam.type = ODP_QUEUE_TYPE_SCHED;
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;
		out_queue = odp_queue_create("crypto-out", &qparam);
	} else if (cargs.poll) {
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		out_queue = odp_queue_create("crypto-out", &qparam);
	}
	if (cargs.schedule || cargs.poll) {
		if (out_queue == ODP_QUEUE_INVALID) {
			app_err("crypto-out queue create failed.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (cargs.schedule) {
		printf("Run in async scheduled mode\n");
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

	memset(thr, 0, sizeof(thr));

	test_run_arg.crypto_args       = cargs;
	test_run_arg.crypto_alg_config = cargs.alg_config;
	test_run_arg.crypto_capa       = crypto_capa;

	if (cargs.alg_config) {
		odph_odpthread_params_t thr_params;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = run_thr_func;
		thr_params.arg      = &test_run_arg;
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		if (cargs.schedule) {
			odph_odpthreads_create(&thr[0], &cpumask, &thr_params);
			odph_odpthreads_join(&thr[0]);
		} else {
			run_measure_one_config(&test_run_arg);
		}
	} else {
		unsigned int i;

		for (i = 0;
		     i < (sizeof(algs_config) / sizeof(crypto_alg_config_t));
		     i++) {
			test_run_arg.crypto_alg_config = algs_config + i;
			run_measure_one_config(&test_run_arg);
		}
	}

	if (cargs.schedule || cargs.poll)
		odp_queue_destroy(out_queue);
	if (odp_pool_destroy(pool)) {
		app_err("Error: pool destroy\n");
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

	return 0;
}

static void parse_args(int argc, char *argv[], crypto_args_t *cargs)
{
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"algorithm", optional_argument, NULL, 'a'},
		{"debug",  no_argument, NULL, 'd'},
		{"flight", optional_argument, NULL, 'f'},
		{"help", no_argument, NULL, 'h'},
		{"iterations", optional_argument, NULL, 'i'},
		{"inplace", no_argument, NULL, 'n'},
		{"payload", optional_argument, NULL, 'l'},
		{"sessions", optional_argument, NULL, 'm'},
		{"reuse", no_argument, NULL, 'r'},
		{"poll", no_argument, NULL, 'p'},
		{"schedule", no_argument, NULL, 's'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:c:df:hi:m:nl:spr";

	cargs->in_place = 0;
	cargs->in_flight = 1;
	cargs->debug_packets = 0;
	cargs->iteration_count = 10000;
	cargs->payload_length = 0;
	cargs->alg_config = NULL;
	cargs->reuse_packet = 0;
	cargs->schedule = 0;

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
		case 'm':
			cargs->max_sessions = atoi(optarg);
			break;
		case 'n':
			cargs->in_place = 1;
			break;
		case 'l':
			cargs->payload_length = atoi(optarg);
			break;
		case 'r':
			cargs->reuse_packet = 1;
			break;
		case 's':
			cargs->schedule = 1;
			break;
		case 'p':
			cargs->poll = 1;
			break;
		default:
			break;
		}
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */

	if ((cargs->in_flight > 1) && cargs->reuse_packet) {
		printf("-f (in flight > 1) and -r (reuse packet) options are not compatible\n");
		usage(argv[0]);
		exit(-1);
	}
	if (cargs->schedule && cargs->poll) {
		printf("-s (schedule) and -p (poll) options are not compatible\n");
		usage(argv[0]);
		exit(-1);
	}
}

/**
 * Prinf usage information
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
	       "  -i, --iterations <number> Number of iterations.\n"
	       "  -n, --inplace	       Encrypt on place.\n"
	       "  -l, --payload	       Payload length.\n"
	       "  -r, --reuse	       Output encrypted packet is passed as input\n"
	       "		       to next encrypt iteration.\n"
	       "  -s, --schedule       Use scheduler for completion events.\n"
	       "  -p, --poll           Poll completion queue for completion events.\n"
	       "  -h, --help	       Display help and exit.\n"
	       "\n");
}
