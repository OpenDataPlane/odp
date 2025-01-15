/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

/**
 * @example odp_crc.c
 *
 * Performance test application for CRC hash APIs
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define KB 1024ull
#define MB (1024ull * 1024ull)

/* Command line options */
typedef struct {
	uint32_t size;
	uint32_t rounds;
	uint32_t offset;
	uint32_t test;
} options_t;

static options_t options;
static const options_t options_def = {
	.size = 16,
	.rounds = 10000,
	.offset = 0,
	.test = 0,
};

static void print_usage(void)
{
	printf("\n"
	       "CRC performance test\n"
	       "\n"
	       "Usage: odp_crc_perf [options]\n"
	       "\n"
	       "  -s, --size    Size of buffer in KB (default %u)\n"
	       "  -r, --rounds  Number of test rounds (default %u)\n"
	       "                Rounded down to nearest multiple of 8\n"
	       "  -o, --offset  Offset of data (default %u)\n"
	       "  -t, --test    Which API to test (default %u)\n"
	       "                0: both\n"
	       "                1: odp_hash_crc32c\n"
	       "                2: odp_hash_crc32\n"
	       "  -h, --help    This help\n"
	       "\n",
	       options_def.size, options_def.rounds, options_def.offset,
	       options.test);
}

static int parse_options(int argc, char *argv[])
{
	int opt;
	int ret = 0;

	static const struct option longopts[] = {
		{ "size", required_argument, NULL, 's' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "offset", required_argument, NULL, 'o' },
		{ "test", required_argument, NULL, 't' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "+s:r:o:t:h";

	options = options_def;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			options.size = atol(optarg);
			break;
		case 'r':
			options.rounds = atol(optarg);
			break;
		case 'o':
			options.offset = atol(optarg);
			break;
		case 't':
			options.test = atol(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (options.size < 1) {
		ODPH_ERR("Invalid size: %" PRIu32 "\n", options.size);
		return -1;
	}

	if (options.offset > 4 * KB) {
		ODPH_ERR("Invalid offset: %" PRIu32 "\n", options.offset);
		return -1;
	}

	if (options.test > 2) {
		ODPH_ERR("Invalid API to test: %" PRIu32 "\n", options.test);
		return -1;
	}

	return ret;
}

static void report(uint64_t nsec)
{
	uint64_t size = (uint64_t)options.size * KB;
	uint32_t rounds = options.rounds & ~7ul;
	double mb, seconds;

	printf("size: %d KB  rounds: %d  offset: %d  ",
	       options.size, rounds, options.offset);
	mb = (double)(size * (uint64_t)rounds) / (double)MB;
	seconds = (double)nsec / (double)ODP_TIME_SEC_IN_NS;
	printf("MB: %.3f  seconds: %.3f  ", mb, seconds);
	printf("MB/s: %.3f", mb / seconds);
	printf("\n\n");
}

static uint64_t measure_crc32c(uint8_t *data, uint32_t size)
{
	void *p = data + options.offset;
	uint32_t crc = 1;
	volatile uint32_t v;
	odp_time_t start = odp_time_local();

	for (uint32_t i = 0; i < options.rounds / 8; i++) {
		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);

		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);
		crc ^= odp_hash_crc32c(p, size, crc);
	}

	/* Make sure that crc is not optimized out. */
	v = crc;

	/* Quell "unused" warning. */
	(void)v;

	return odp_time_diff_ns(odp_time_local(), start);
}

static void test_odp_hash_crc32c(uint8_t *data)
{
	uint64_t size = (uint64_t)options.size * KB;
	uint64_t nsec;

	/* Warm-up. */
	measure_crc32c(data, size);

	/* Actual measurement. */
	nsec = measure_crc32c(data, size);

	report(nsec);
}

static uint64_t measure_crc32(uint8_t *data, uint32_t size)
{
	void *p = data + options.offset;
	uint32_t crc = 1;
	volatile uint32_t v;
	odp_time_t start = odp_time_local();

	for (uint32_t i = 0; i < options.rounds / 8; i++) {
		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);

		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);
		crc ^= odp_hash_crc32(p, size, crc);
	}

	/* Make sure that crc is not optimized out. */
	v = crc;

	/* Quell "unused" warning. */
	(void)v;

	return odp_time_diff_ns(odp_time_local(), start);
}

static void test_odp_hash_crc32(uint8_t *data)
{
	uint64_t size = (uint64_t)options.size * KB;
	uint64_t nsec;

	/* Warm-up. */
	measure_crc32(data, size);

	/* Actual measurement. */
	nsec = measure_crc32(data, size);

	report(nsec);
}

int main(int argc, char **argv)
{
	odp_instance_t instance;
	odp_init_t init;

	if (parse_options(argc, argv))
		exit(EXIT_FAILURE);

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.stash = 1;
	init.not_used.feat.timer = 1;
	init.not_used.feat.tm = 1;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	uint8_t *buf, *data;
	uint32_t size = options.size * KB;
	uint64_t seed = 1;
	const unsigned long page = 4 * KB;

	/* One extra page for alignment, another one for offset. */
	buf = (uint8_t *)malloc(size + page * 2);

	if (!buf) {
		ODPH_ERR("Memory allocation failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Align to start of page. */
	data = (uint8_t *)(((uintptr_t)buf + (page - 1)) & ~(page - 1));

	if (odp_random_test_data(data, size, &seed) != (int32_t)size) {
		ODPH_ERR("odp_random_test_data() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (options.test == 0 || options.test == 1) {
		printf("odp_hash_crc32c\n"
		       "---------------\n");
		test_odp_hash_crc32c(data);
	}

	if (options.test == 0 || options.test == 2) {
		printf("odp_hash_crc32\n"
		       "--------------\n");
		test_odp_hash_crc32(data);
	}

	free(buf);

	if (odp_term_local()) {
		ODPH_ERR("Local terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
