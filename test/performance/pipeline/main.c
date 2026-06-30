/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include <odp/helper/odph_api.h>

#include "config_parser.h"
#include "orchestrator.h"

#define PROG_NAME "odp_pipeline"

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

static void print_usage(void)
{
	printf("\n"
	       "Generic ODP performance tester. Define pipelines and workflows to be run.\n"
	       "\n"
	       "Usage: " PROG_NAME " OPTIONS\n"
	       "\n"
	       "  E.g. " PROG_NAME " -f /path/to/config_file\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "\n"
	       "  -f, --config_file Path to configuration file.\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -l, --lib         Path to a shared library providing additional work. May be\n"
	       "                    given multiple times. Work registered by a library overrides\n"
	       "                    baseline work of the same name.\n"
	       "  -h, --help        This help.\n"
	       "\n");
}

static parse_result_t parse_options(int argc, char **argv, opts_t *opts)
{
	int opt;

	static const struct option longopts[] = {
		{ "config_file", required_argument, NULL, 'f' },
		{ "lib", required_argument, NULL, 'l' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "f:l:h";

	memset(opts, 0, sizeof(*opts));

	while (true) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'f':
			free(opts->path);
			opts->path = strdup(optarg);

			if (opts->path == NULL) {
				ODPH_ERR("Error allocating memory\n");
				return PRS_NOK;
			}

			break;
		case 'l': {
			char **libs = realloc(opts->libs, (opts->num_libs + 1U) * sizeof(*libs));

			if (libs == NULL) {
				ODPH_ERR("Error allocating memory\n");
				return PRS_NOK;
			}

			opts->libs = libs;
			opts->libs[opts->num_libs] = strdup(optarg);

			if (opts->libs[opts->num_libs] == NULL) {
				ODPH_ERR("Error allocating memory\n");
				return PRS_NOK;
			}

			++opts->num_libs;
			break;
		}
		case 'h':
			print_usage();
			return PRS_TERM;
		case '?':
		default:
			print_usage();
			return PRS_NOK;
		}
	}

	return PRS_OK;
}

static void free_options(opts_t *opts)
{
	for (uint32_t i = 0U; i < opts->num_libs; ++i)
		free(opts->libs[i]);

	free(opts->libs);
	free(opts->path);
}

int main(int argc, char **argv)
{
	opts_t opts;
	parse_result_t parse_res;
	int ret = EXIT_SUCCESS;
	/* No support for process mode so no helper argument parsing */
	parse_res = parse_options(argc, argv, &opts);

	if (parse_res != PRS_OK) {
		free_options(&opts);

		return parse_res == PRS_NOK ? EXIT_FAILURE : EXIT_SUCCESS;
	}

	if (orchestrator_init() && config_parser_init(&opts) && config_parser_deploy()) {
		orchestrator_deploy();
	} else {
		ODPH_ERR("Error initializing pipeline\n");
		ret = EXIT_FAILURE;
	}

	config_parser_destroy();
	orchestrator_destroy();
	free_options(&opts);

	return ret;
}
