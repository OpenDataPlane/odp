/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/* This file measures performance for odp compression and decompression API's.
 *
 * It compresses or decompresses the input provided to stdin
 * and optionally writes to output file.
 *
 * Test is a single-threaded application which only measure
 * compression/decompression throughput for given input file.
 * It also provide ability to user to input different compression level.
 * Compression level is ignored for decompression case.
 * Current test operates on packets and process input up to maximum packet
 * segment data length (which may vary across different odp implementation).
 *
 * Options:
 * --------
 * Run
 * "./odp_comp_perf_file -h" for more help.
 *
 */

#include "config.h"

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

#define app_info(fmt, ...) \
	fprintf(stderr, "%s:%d:%s(): Info: " fmt, __FILE__, \
		__LINE__, __func__, ##__VA_ARGS__)

/** @def POOL_NUM_PKT
 * Number of packets in the pool
 */
#define POOL_NUM_PKT  64

/** @def POOL_NAME
 * Name of the pool to use
 */
#define POOL_NAME "packet_pool"

/** @def QUEUE_NAME
 * Name of the output queue
 */
#define QUEUE_NAME "comp-out"

/**
 * Structure that holds template for session create call
 * for different algorithms supported by test
 */
typedef struct {
	const char *name;		      /**< Algorithm name */
	odp_comp_session_param_t session; /**< Prefilled comp session params */
} comp_alg_config_t;

/**
 * Parsed command line comp/decomp arguments. Describes test configuration.
 */
typedef struct {
	/**
	 * Number of iterations to repeat comp/decomp operation to get good
	 * average number. Specified through -i or --iterations option.
	 * Default is 1.
	 */
	int iteration_count;

	/**
	 * Pointer to selected algorithm to test. Name of algorithm is passed
	 * through -a or --algorithm option and is a mandatory option.
	 */
	comp_alg_config_t *alg_config;

	/**
	 * Use sync or async mode to get result from comp operation. For output
	 * result, queue will be polled. Specified through -p (poll) argument.
	 */
	int poll;

	/**
	 * Operation type. Specified through -d or --decomp option for decompression
	 * and -c or --comp option for compression. For comp this is set to 0.
	 * Redirecting input to stdin is mandatory.
	 */
	int decomp;

	/** Compression level, specified through -l (--level) option */
	unsigned int level;

	/**
	 * Output buffer size. By default, max size supported by implementation
	 * (if non-zero) or maz_seg_len. Better to use max size to avoid out of
	 * space error in order to get good performance numbers.
	 */
	unsigned int outbuf_size;

	/**
	 * Name of file to write output to, enabled when user provides output file
	 */
	char *out_file;
	FILE *out_fptr;

} comp_args_t;

/*
 * Helper structure that holds averages for test of one algorithm
 * for given payload size.
 */
typedef struct {
	/** Total elapsed time for comp/decomp operation. */
	double total_elapsed;

	/** Total length of input data processed */
	unsigned int tot_input_len;

} comp_run_result_t;

/**
 * Structure holds one snap to misc times of current process.
 */
typedef struct {
	struct timeval tv;	 /**< Total elapsed time */
} time_record_t;

static void parse_args(int argc, char *argv[], comp_args_t *cargs);
static void usage(char *progname);

static int compress_packet(odp_comp_op_param_t *op_params,
			   comp_args_t *cargs,
			   odp_queue_t out_queue,
			   odp_comp_op_result_t *comp_result);

static int decompress_packet(odp_comp_op_param_t *op_params,
			     comp_args_t *cargs,
			     odp_queue_t out_queue,
			     odp_comp_op_result_t *comp_result);

int write_out_data(odp_comp_op_result_t *result, FILE *out);

/**
 * Chunksize for compressing/decompressing, set in main(),
 * equal to max_seg_len
 */
static unsigned int payload_len;

/** Set of known algorithms to test */
static comp_alg_config_t algs_config[] = {
	{
		.name    = "deflate",
		.session = {
			.comp_algo    = ODP_COMP_ALG_DEFLATE,
			.hash_algo    = ODP_COMP_HASH_ALG_NONE,
			.compl_queue  = ODP_QUEUE_INVALID,
			.mode         = ODP_COMP_SYNC,
		},
	},
	{
		.name    = "zlib",
		.session = {
			.comp_algo    = ODP_COMP_ALG_ZLIB,
			.hash_algo    = ODP_COMP_HASH_ALG_NONE,
			.compl_queue  = ODP_QUEUE_INVALID,
			.mode         = ODP_COMP_SYNC,
		},
	},
};

/**
 * Find corresponding config for given name. Returns NULL
 * if config for given name is not found.
 */
static comp_alg_config_t *
find_config_by_name(const char *name) {
	unsigned int i;
	comp_alg_config_t *ret = NULL;

	for (i = 0; i < (sizeof(algs_config) / sizeof(comp_alg_config_t));
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

	for (i = 0; i < (sizeof(algs_config) / sizeof(comp_alg_config_t));
	     i++) {
		fprintf(stderr, "%s %s\n", prefix, algs_config[i].name);
	}
}

/** Snap current time values and put them into 'rec' */
static void
fill_time_record(time_record_t *rec)
{
	gettimeofday(&rec->tv, NULL);
}

/** Get diff of elapsed time between two time snap records */
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

#define REPORT_HEADER	"\n%30.30s %15s %15s %15s %15s\n"
#define REPORT_LINE	    "%30.20s %15d %15d %15.3f %15d\n\n"

/** Print header line for our report */
static void
print_result_header(comp_args_t *cargs)
{
	fprintf(stderr, "  Operation       %s\n",
		cargs->decomp ? "Decompression" : "Compression");
	fprintf(stderr, "  Operation mode  %s\n",
		cargs->poll ? "Async polling" : "Sync");

	fprintf(stderr, REPORT_HEADER,
		"Algorithm", "Iterations", "Chunksize(bytes)",
		"Time elapsed(us)", "Throughput(KBps)");
}

/** Print one line of our report */
static void
print_result(comp_args_t *cargs,
	     comp_alg_config_t *config,
	     comp_run_result_t *result)
{
	unsigned int throughput;

	throughput = (1000000.0 / result->total_elapsed)
			* result->tot_input_len / 1024;
	fprintf(stderr, REPORT_LINE,
		config->name, cargs->iteration_count, payload_len,
		/*result->tot_input_len / cargs->iteration_count,*/
		result->total_elapsed, throughput);
}

/** Create ODP session for given config. */
static int
create_session_from_config(odp_comp_session_t *session,
			   comp_alg_config_t *config,
			   comp_args_t *cargs)
{
	odp_comp_session_param_t params;
	odp_comp_ses_create_err_t ses_create_rc;
	odp_queue_t out_queue;

	odp_comp_session_param_init(&params);
	memcpy(&params, &config->session, sizeof(odp_comp_session_param_t));

	params.comp_algo = config->session.comp_algo;
	params.hash_algo = config->session.hash_algo;

	if (cargs->decomp) {
		params.op = ODP_COMP_OP_DECOMPRESS;
	} else {
		params.op = ODP_COMP_OP_COMPRESS;

		if (config->session.comp_algo == ODP_COMP_ALG_DEFLATE)
			params.algo_param.deflate.level = cargs->level;
		else if (config->session.comp_algo == ODP_COMP_ALG_ZLIB)
			params.algo_param.zlib.def.level = cargs->level;
	}

	if (cargs->poll) {
		out_queue = odp_queue_lookup(QUEUE_NAME);
		if (out_queue == ODP_QUEUE_INVALID) {
			app_err("%s queue not found\n", QUEUE_NAME);
			return -1;
		}
		params.compl_queue = out_queue;
		params.mode = ODP_COMP_ASYNC;
	} else {
		params.compl_queue = ODP_QUEUE_INVALID;
		params.mode = ODP_COMP_SYNC;
	}
	if ((odp_comp_session_create(&params, session,
				     &ses_create_rc)) &&
	    (ses_create_rc != ODP_COMP_SES_CREATE_ERR_NONE)) {
		app_err("session create failed.\n");
		return -1;
	}

	return 0;
}

/** Compress a packet */
static int compress_packet(odp_comp_op_param_t *op_params,
			   comp_args_t           *cargs,
			   odp_queue_t           out_queue,
			   odp_comp_op_result_t  *comp_result)
{
	int rc = 0;

	if (cargs->poll) {
		odp_packet_t ev_packet;
		odp_event_t event;

		rc = odp_comp_compress_enq(op_params);
		if (rc < 0) {
			app_err("failed odp_comp_compress_enq: rc = %d\n",
				rc);
			return -1;
		}

		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(out_queue);
		} while (event == ODP_EVENT_INVALID);

		if ((odp_event_type(event) != ODP_EVENT_PACKET) ||
		    (odp_event_subtype(event) !=
		     ODP_EVENT_PACKET_COMP)) {
			return -1;
		}

		ev_packet = odp_comp_packet_from_event(event);
		rc = odp_comp_result(ev_packet, comp_result);
		if (rc < 0) {
			app_err("failed to get comp result: rc = %d\n",
				rc);
			return rc;
		}

	} else {
		rc = odp_comp_compress(op_params, comp_result);
		if (rc < 0) {
			app_err("failed odp_comp_compress: rc = %d\n",
				rc);
			return rc;
		}
	}

	return 0;
}

/** Decompress packet */
static int decompress_packet(odp_comp_op_param_t *op_params,
			     comp_args_t           *cargs,
			     odp_queue_t           out_queue,
			     odp_comp_op_result_t  *comp_result)
{
	int rc = 0;

	if (cargs->poll) {
		odp_packet_t ev_packet;
		odp_event_t event;

		rc = odp_comp_decomp_enq(op_params);
		if (rc < 0) {
			app_err("failed odp_comp_decomp_enq: rc = %d\n",
				rc);
			return -1;
		}

		/* Poll completion queue for results */
		do {
			event = odp_queue_deq(out_queue);
		} while (event == ODP_EVENT_INVALID);

		if ((odp_event_type(event) != ODP_EVENT_PACKET) ||
		    (odp_event_subtype(event) !=
		    ODP_EVENT_PACKET_COMP)) {
			return -1;
		}

		ev_packet = odp_comp_packet_from_event(event);
		rc = odp_comp_result(ev_packet, comp_result);

	} else {
		rc = odp_comp_decomp(op_params, comp_result);
	}

	return rc;
}

int write_out_data(odp_comp_op_result_t *result, FILE *out)
{
	uint32_t len = 0;
	uint32_t offset;
	uint8_t *data;
	uint32_t end;
	odp_packet_t out_pkt = result->output.pkt.packet;

	offset = result->output.pkt.data_range.offset;
	end = offset + result->output.pkt.data_range.length;

	while (offset < end) {
		data = odp_packet_offset(out_pkt, offset, &len, NULL);
		/* len gives segment length at ptr 'data' and is not actual
		 * data available
		 * in buffer. So check and adjust that we dont exceed limit here
		 */
		if (offset + len > end)
			len = end - offset;

		fwrite(data, 1, len, out);
		offset += len;
	}
	return 0;
}

/**
 * Run measurement iterations for given config.
 * Result of run returned in 'result' out parameter.
 */
static int
run_measure_one(comp_args_t *cargs,
		FILE                *input,
		comp_alg_config_t   *config,
		comp_run_result_t   *result)
{
	odp_comp_session_t    session;
	odp_comp_op_param_t   op_params;
	odp_comp_op_result_t  comp_result;
	odp_pool_t             pkt_pool;
	odp_queue_t            out_queue;
	odp_packet_t           in_pkt, out_pkt;
	uint8_t                *data = NULL;
	int                    rc = 0;
	int	                   iterations = 0;
	unsigned int	       read = 0;
	unsigned int           in_len, out_len;
	unsigned int           flen = 0;
	time_record_t          start, end;

	/* Create session */
	if (create_session_from_config(&session, config, cargs))
		return -1;

	pkt_pool = odp_pool_lookup(POOL_NAME);
	if (pkt_pool == ODP_POOL_INVALID) {
		app_err("%s not found\n", POOL_NAME);
		odp_comp_session_destroy(session);
		return -1;
	}

	if (cargs->poll) {
		out_queue = odp_queue_lookup(QUEUE_NAME);
		if (out_queue == ODP_QUEUE_INVALID) {
			app_err("%s queue not found\n", QUEUE_NAME);
			odp_comp_session_destroy(session);
			return -1;
		}
	} else {
		out_queue = ODP_QUEUE_INVALID;
	}

	in_pkt = odp_packet_alloc(pkt_pool, payload_len);
	if (in_pkt == ODP_PACKET_INVALID) {
		app_err("failed to allocate in_pkt\n");
		odp_comp_session_destroy(session);
		return -1;
	}

	out_len = cargs->outbuf_size;
	out_pkt = odp_packet_alloc(pkt_pool, out_len);
	if (out_pkt == ODP_PACKET_INVALID) {
		app_err("failed to allocate out_pkt\n");
		rc = -1;
		goto free_in;
	}

	fseek(input, 0, SEEK_END);
	flen = ftell(input);

	data = odp_packet_data(in_pkt);

	while (!rc && iterations++ < cargs->iteration_count) {
		fseek(input, 0, SEEK_SET);
		read = 0;

		/* read max_seg_len data from file at a time and process */
		while (!rc && read < flen) {
			/* Read len data from file */
			in_len = odp_packet_seg_len(in_pkt);
			in_len = fread(data, 1, in_len, input);
			if (ferror(input)) {
				app_err("error while reading from stdin\n");
				rc = -1;
				break;
			}

			op_params.input.pkt.packet             = in_pkt;
			op_params.input.pkt.data_range.offset  = 0;
			op_params.input.pkt.data_range.length  = in_len;
			op_params.output.pkt.packet            = out_pkt;
			op_params.output.pkt.data_range.offset = 0;
			op_params.output.pkt.data_range.length = out_len;
			op_params.session                      = session;

			read += in_len;
			if (read >= flen)
				op_params.last = 1;
			else
				op_params.last = 0;

			fill_time_record(&start);
			do {
				if (cargs->decomp)
					rc = decompress_packet(&op_params,
							       cargs,
							       out_queue,
							       &comp_result);
				else
					rc = compress_packet(&op_params,
							     cargs,
							     out_queue,
							     &comp_result);

				if (rc < 0) {
					app_err("failed to %s: rc = %d\n",
						cargs->decomp ?
						"decompress" : "compress", rc);
					break;
				}
				if (cargs->out_fptr)
					write_out_data(&comp_result,
						       cargs->out_fptr);
			} while (comp_result.err == ODP_COMP_ERR_OUT_OF_SPACE);

			fill_time_record(&end);

			{
				double count;

				count = get_elapsed_usec(&start, &end);
				result->total_elapsed += count;
			}

		} /* Done processing file */
	} /* Iterations to process file */

	result->tot_input_len = cargs->iteration_count * flen;

	odp_packet_free(out_pkt);
free_in:
	odp_packet_free(in_pkt);

	odp_comp_session_destroy(session);
	return rc;
}

/** Process one algorithm */
static int
run_measure_one_config(comp_args_t *cargs,
		       comp_alg_config_t *config)
{
	comp_run_result_t       result;
	odp_comp_capability_t  capa;
	int                     rc = 0;

	memset(&result, 0, sizeof(result));

	/* Check comp capabilities */
	rc = odp_comp_capability(&capa);

	if (config->session.comp_algo == ODP_COMP_ALG_NULL &&
	    !(capa.comp_algos.bit.null))
		rc = -1;
	if (config->session.comp_algo == ODP_COMP_ALG_DEFLATE &&
	    !(capa.comp_algos.bit.deflate))
		rc = -1;
	if (config->session.comp_algo == ODP_COMP_ALG_ZLIB &&
	    !(capa.comp_algos.bit.zlib))
		rc = -1;
	if (config->session.comp_algo == ODP_COMP_ALG_LZS &&
	    !(capa.comp_algos.bit.lzs))
		rc = -1;
	if (config->session.hash_algo == ODP_COMP_HASH_ALG_SHA1 &&
	    !(capa.hash_algos.bit.sha1))
		rc = -1;
	if (config->session.hash_algo == ODP_COMP_HASH_ALG_SHA256 &&
	    !(capa.hash_algos.bit.sha256))
		rc = -1;
	if (rc < 0) {
		app_err("capabilities do not match\n");
		return rc;
	}

	/* Open outfile to write if provided */
	if (cargs->out_file) {
		cargs->out_fptr = fopen(cargs->out_file, "wb");
		if (cargs->out_fptr == NULL) {
			app_err("Unable to open output file: %s\n",
				cargs->out_file);
			return -1;
		}
	}

	print_result_header(cargs);

	rc = run_measure_one(cargs, stdin, config, &result);
	if (rc < 0) {
		app_err("failed to measure\n");
		return rc;
	}

	print_result(cargs, config, &result);

	return rc;
}

int main(int argc, char *argv[])
{
	comp_args_t           cargs;
	odp_pool_t            pool;
	odp_queue_param_t     qparam;
	odp_pool_param_t      params;
	odp_queue_t           out_queue = ODP_QUEUE_INVALID;
	odp_instance_t        instance;
	odp_pool_capability_t capa;
	uint32_t              max_seg_len;

	memset(&cargs, 0, sizeof(cargs));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &cargs);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		app_err("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	odp_init_local(instance, ODP_THREAD_WORKER);

	if (odp_pool_capability(&capa)) {
		app_err("Pool capability request failed.\n");
		exit(EXIT_FAILURE);
	}

	max_seg_len = capa.pkt.max_seg_len;
	payload_len = max_seg_len;

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = max_seg_len;
	params.pkt.len	   = max_seg_len;
	params.pkt.num	   = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create(POOL_NAME, &params);

	if (pool == ODP_POOL_INVALID) {
		app_err("packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	odp_queue_param_init(&qparam);
	if (cargs.poll) {
		qparam.type = ODP_QUEUE_TYPE_PLAIN;
		out_queue = odp_queue_create(QUEUE_NAME, &qparam);

		if (out_queue == ODP_QUEUE_INVALID) {
			odp_pool_destroy(pool);
			app_err("%s queue create failed.\n", QUEUE_NAME);
			exit(EXIT_FAILURE);
		}
	}

	if (run_measure_one_config(&cargs, cargs.alg_config))
		app_err("Failed to measure\n");

	if (cargs.poll)
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

static void parse_args(int argc, char *argv[], comp_args_t *cargs)
{
	int                        opt, rc;
	int                        long_index;
	unsigned int               max_len;
	odp_pool_capability_t      pool_capa;
	odp_comp_alg_capability_t  capa;

	static const struct option longopts[] = {
		{"algorithm", required_argument, NULL, 'a'}, /* mandatory */
		{"outfile", required_argument, NULL, 'o'}, /* mandatory */
		{"help", no_argument, NULL, 'h'},
		{"iterations", required_argument, NULL, 'i'},
		{"poll", no_argument, NULL, 'p'},
		/* make it mandatory, comp or decomp */
		{"decomp", no_argument, NULL, 'd'},
		/* make it mandatory, comp or decomp */
		{"comp", no_argument, NULL, 'c'},
		{"level", required_argument, NULL, 'l'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+a:o:hi:pdcl:s:"; /* check */

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	/* Get capabilities */
	rc = odp_pool_capability(&pool_capa);
	if (rc < 0) {
		app_err("failed to get pool capabilities\n");
		exit(EXIT_FAILURE);
	}

	max_len = pool_capa.pkt.max_len;
	if (max_len == 0)
		max_len = payload_len;

	cargs->iteration_count = 1;
	cargs->alg_config      = NULL;
	cargs->poll            = 0;
	cargs->decomp          = 0;
	cargs->level           = ODP_COMP_LEVEL_MIN;
	cargs->out_file        = NULL;
	cargs->out_fptr        = NULL;
	cargs->outbuf_size     = max_len;

	opterr = 0; /* do not issue errors on helper options */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'a':
			cargs->alg_config = find_config_by_name(optarg);
			if (!cargs->alg_config) {
				app_err("cannot test comp '%s' configuration\n",
					optarg);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			cargs->iteration_count = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'p':
			cargs->poll = 1;
			break;
		case 'd':
			cargs->decomp = 1;
			break;
		case 'c':
			cargs->decomp = 0;
			break;
		case 'l':
			cargs->level = atoi(optarg);
			break;
		case 'o':
			cargs->out_file = optarg;
			break;
		case 's':
			cargs->outbuf_size = atoi(optarg);
			if (cargs->outbuf_size > max_len) {
				app_info("Max out buf size supported: %u,"
					 "resetting it\n", max_len);
				cargs->outbuf_size = max_len;
			}
			break;

		default:
			break;
		}
	}

	if (!cargs->alg_config) {
		app_err("Please provide algorithm\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	rc = odp_comp_alg_capability(cargs->alg_config->session.comp_algo,
				     &capa, 1);
	if (rc < 0) {
		app_err("failed to get algo capabilities\n");
		exit(EXIT_FAILURE);
	}

	if (cargs->level > capa.max_level) {
		app_err("Max level supported for %s is: %d\n",
			cargs->alg_config->name, capa.max_level);
		exit(EXIT_FAILURE);
	}

	/* dont allow both -c and -d options at once */
	optind = 1; /* reset 'extern optind' from the getopt lib */
}

/**
 * Print usage information
 */
static void usage(char *progname)
{
	fprintf(stderr, "\n"
		"OpenDataPlane compression/decompression speed measure.\n\n"
		"Usage: %s OPTIONS < input_file_name\n"
		"  E.g. %s -a zlib -c -o out_file_name < input_file_name\n"
		"\n"
		"OPTIONS\n",
		progname, progname);

	fprintf(stderr,
		"  -a, --algorithm <name> Specify algorithm name (mandatory)\n"
		"                          Supported values are:\n");
		print_config_names("                              ");

	fprintf(stderr,
		"  -i, --iterations <number> Number of iterations.\n"
		"  -d, --decomp              Decompression speed measure\n"
		"  -s, --outsize <number>    Output bufer size\n"
		"  -o, --outfile <name>      Output file name to write\n"
		"                            comp/decomp result\n"
		"                            NOTE: For perf measurement,\n"
		"                            it is recommended to not use\n"
		"                            output(dest) file to write\n"
		"                            output. Make sure\n"
		"                            #iterations is 1\n"
		"  -c, --comp                Compression speed measure\n"
		"  -l, --level               Compression level\n"
		"  -p, --poll                Poll completion queue\n"
		"                            for completion\n"
		"                            events (async mode)\n"
		"  -h, --help                Display help and exit\n"
		"\n");
}
