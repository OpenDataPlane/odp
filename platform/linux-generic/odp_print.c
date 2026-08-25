/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include <stdarg.h>
#include <stdio.h>

#define PRINT_BUF_SIZE 4096

typedef struct {
	/* Buffering nesting level, zero when not buffering */
	int depth;
	/* Number of characters in the buffer, without the end mark */
	int len;
	char buf[PRINT_BUF_SIZE];

} print_local_t;

static __thread print_local_t print_local;

static void flush_buffer(print_local_t *local)
{
	if (local->len == 0)
		return;

	_odp_log_fn_get()(ODP_LOG_PRINT, "%s", local->buf);
	local->len = 0;
}

void _odp_print_term_local(void)
{
	if (print_local.depth == 0)
		return;

	_ODP_ERR("Print buffering not stopped (depth %d)\n", print_local.depth);

	print_local.depth = 0;
	flush_buffer(&print_local);
}

#include <odp/visibility_begin.h>

int _odp_print_buffering(void)
{
	return print_local.depth > 0;
}

void _odp_print_buffering_start(void)
{
	if (print_local.depth == 0)
		print_local.len = 0;

	print_local.depth++;
}

void _odp_print_buffering_stop(void)
{
	if (print_local.depth == 0) {
		_ODP_ERR("Print buffering not started\n");
		return;
	}

	print_local.depth--;

	if (print_local.depth == 0)
		flush_buffer(&print_local);
}

ODP_PRINTF_FORMAT(1, 2)
void _odp_print_buffered(const char *fmt, ...)
{
	print_local_t *local = &print_local;
	va_list args, args_copy;
	int space = PRINT_BUF_SIZE - local->len;
	int len;

	va_start(args, fmt);
	va_copy(args_copy, args);
	len = vsnprintf(&local->buf[local->len], space, fmt, args);
	va_end(args);

	if (len < 0) {
		local->buf[local->len] = 0;
		goto out;
	}

	if (len < space) {
		local->len += len;
		goto out;
	}

	/* Did not fit. Drop the partial print, flush the buffer and retry with
	 * the whole buffer available. */
	local->buf[local->len] = 0;
	flush_buffer(local);

	len = vsnprintf(local->buf, PRINT_BUF_SIZE, fmt, args_copy);

	if (len < 0) {
		local->buf[0] = 0;
		goto out;
	}

	/* A single print larger than the buffer gets truncated */
	if (len >= PRINT_BUF_SIZE) {
		_ODP_ERR("Print buffer size %d exceeded, output truncated\n", PRINT_BUF_SIZE);
		len = PRINT_BUF_SIZE - 1;
	}

	local->len = len;

out:
	va_end(args_copy);
}

#include <odp/visibility_end.h>
