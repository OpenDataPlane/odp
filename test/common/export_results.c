/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "export_results.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/** Maximum length of output path/name */
#define MAX_FILENAME_LEN 192

typedef struct {
	test_common_options_t common_options;

	char filename[MAX_FILENAME_LEN];

	FILE *file;

	char *args;

	int init_done;

} test_export_gbl_t;

static test_export_gbl_t gbl_data;

static void extract_options(int argc, char *argv[])
{
	int total_len = 1;
	int len = 0;
	int i, ret;

	for (i = 1; i < argc; i++)
		total_len += strlen(argv[i]) + 1;

	gbl_data.args = (char *)calloc(total_len, sizeof(char));
	if (!gbl_data.args) {
		ODPH_ERR("Memory allocation failed\n");
		return;
	}

	for (i = 1; i < argc; i++) {
		ret = snprintf(gbl_data.args + len, total_len - len, " %s", argv[i]);
		if (ret >= total_len - len || ret < 0) {
			ODPH_ERR("snprintf() error.\n");
			free(gbl_data.args);
			gbl_data.args = NULL;
			return;
		}
		len += ret;
	}
}

int test_common_parse_options(int argc, char *argv[])
{
	char *env;
	int i, j;

	env = getenv("TEST_COMMON_EXPORT");
	if (env) {
		gbl_data.common_options.is_export = true;
		odph_strcpy(gbl_data.filename, env, MAX_FILENAME_LEN);
	}

	/* Find and remove option */
	for (i = 0; i < argc;) {
		if (strcmp(argv[i], "--test-common-export") == 0) {
			gbl_data.common_options.is_export = true;
			if (i + 1 < argc && argv[i + 1][0] != '-') {
				odph_strcpy(gbl_data.filename, argv[i + 1],
					    MAX_FILENAME_LEN);
				for (j = i; j < argc - 2; j++)
					argv[j] = argv[j + 2];
				argc -= 2;
				continue;
			} else {
				odph_strcpy(gbl_data.filename, argv[0],
					    MAX_FILENAME_LEN);
				for (j = i; j < argc - 1; j++)
					argv[j] = argv[j + 1];
				argc--;
			}
		}
		i++;
	}

	if (gbl_data.common_options.is_export) {
		if (strlen(gbl_data.filename) == 0)
			odph_strcpy(gbl_data.filename, argv[0], MAX_FILENAME_LEN);
		extract_options(argc, argv);
	}

	return argc;
}

int test_common_options(test_common_options_t *options)
{
	const char *extension = ".csv";
	size_t ext_len = strlen(extension);
	size_t filename_len = strlen(gbl_data.filename);

	memset(options, 0, sizeof(*options));

	options->is_export = gbl_data.common_options.is_export;

	if (!options->is_export || gbl_data.init_done)
		return 0;

	gbl_data.init_done = 1;

	/* Add extension if needed */
	if (filename_len < ext_len ||
	    strcmp(gbl_data.filename + filename_len - ext_len, extension) != 0) {
		if (filename_len + ext_len >= MAX_FILENAME_LEN) {
			ODPH_ERR("Not enough space to add '%s' to %s\n",
				 extension, gbl_data.filename);
			return -1;
		}
		strcat(gbl_data.filename, extension);
	}

	gbl_data.file = fopen(gbl_data.filename, "w");
	if (!gbl_data.file) {
		ODPH_ERR("Failed to open file %s: %s\n",
			 gbl_data.filename, strerror(errno));
		return -1;
	}

	if (gbl_data.args) {
		if (fprintf(gbl_data.file, "#%.*s;%s\n", (int)filename_len,
			    gbl_data.filename, gbl_data.args) < 0) {
			ODPH_ERR("Writing filename and args failed\n");
			return -1;
		}
		fflush(gbl_data.file);
		free(gbl_data.args);
	}

	return 0;
}

int test_common_write(const char *fmt, ...)
{
	va_list args, args_copy;
	int len, ret;

	va_start(args, fmt);
	va_copy(args_copy, args);

	len = vsnprintf(NULL, 0, fmt, args);
	ret = vfprintf(gbl_data.file, fmt, args_copy);

	va_end(args);
	va_end(args_copy);

	if (len != ret) {
		ODPH_ERR("Expected %i characters to be written, actually wrote: %i", len, ret);
		return -1;
	}

	return 0;
}

void test_common_write_term(void)
{
	if (gbl_data.file == NULL) {
		ODPH_ERR("Warning: there is no open file to be closed\n");
		return;
	}

	(void)fclose(gbl_data.file);
}
