/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 Nokia
 */

#ifndef EXPORT_RESULT_H
#define EXPORT_RESULT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

typedef struct {
	/** Export results or no */
	odp_bool_t is_export;
} test_common_options_t;

/**
* Parse test options.
*
* Parse commonly used universal test options.
*
* Exports test results as /path/to/test-dir/<test>.csv by default.
* Optional argument should be the full path of the output file including filename.
*
* Ways to define export:
* 1. Option: --test-common-export <optional path>
* 2. Environment variable: TEST_COMMON_EXPORT=<optional_path>
*
* Path priority:
* 1. Command line option --test-common-export.
*	If a path is provided with this option, it is always used.
*	If this option is used without a path, default path is used, regardless of the env var.
* 2. Environment variable TEST_COMMON_EXPORT
*	If the command line option is not used, the path provided by this env var is used.
*	If no path is provided here, and the previous option is not used, results won't be exported.
*
* Returns new argument count. Original argument count decremented by the number of removed options.
*/
int test_common_parse_options(int argc, char *argv[]);

/**
* Get test options
*
* Return used test options. test_common_parse_options() must be called before
* using this function.
*
* Returns 0 on success, -1 on failure
*/
int test_common_options(test_common_options_t *options);

/**
* Export test results
*
* Only call this function after test_common_options() returns is_export = true.
*
* Lines should be separated by "\n" and the first line should contain the column headers.
* Lower case letters should be preferred, exception being metric prefixes i.e.
* M for mega etc. where capitalization matters.
* Columns are separated by commas i.e.
* function name, average cpu cycles per function call
* odp_buffer_from_event,0.366660
* odp_buffer_from_event_multi,11.889800
* ...
* odp_event_flow_id_set,3.555640
*
* Returns 0 on success, -1 on failure
*/
ODP_PRINTF_FORMAT(1, 2)
int test_common_write(const char *fmt, ...);

/**
 * Terminate writing
 *
 * Called after last write. Do not call test_common_write after calling this.
 */
void test_common_write_term(void);

#ifdef __cplusplus
}
#endif

#endif
