/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <stdint.h>
#include <stdlib.h>

#include <odp/helper/odph_api.h>
#include <sys/queue.h>

#include "common.h"
#include "config_parser.h"
#include "work.h"

typedef struct work_entry_s {
	TAILQ_ENTRY(work_entry_s) w;

	const char *name;
	work_init_fn_t init_fn;
	work_print_fn_t print_fn;
	work_destroy_fn_t destroy_fn;
} work_entry_t;

typedef struct {
	TAILQ_HEAD(, work_entry_s) w;

	odp_bool_t init_done;
} work_entries_t;

typedef struct ODP_ALIGNED_CACHE {
	work_fn_t fn;
	uintptr_t data;
	work_entry_t *entry;
	work_stats_t stats;
} work_priv_t;

static work_entries_t entries;

work_t work_create_work(const work_param_t *param)
{
	work_priv_t *work = calloc(1U, sizeof(*work));
	work_entry_t *entry;
	work_init_t init;

	if (work == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	TAILQ_FOREACH(entry, &entries.w, w) {
		if (strcmp(entry->name, param->type) != 0)
			continue;

		entry->init_fn(param, &init);
		work->fn = init.fn;
		work->data = init.data;
		work->entry = entry;
		return (work_t)work;
	}

	ODPH_ABORT("No work found (%s), aborting\n", param->type);
}

int work_issue(work_t work, odp_event_t ev[], int num)
{
	work_priv_t *priv = (work_priv_t *)work;

	return priv->fn(priv->data, ev, num, &priv->stats);
}

void work_register_work(const char *name, work_init_fn_t init_fn, work_print_fn_t print_fn,
			work_destroy_fn_t destroy_fn)
{
	work_entry_t *entry = calloc(1U, sizeof(*entry));

	if (entry == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	entry->name = name;
	entry->init_fn = init_fn;
	entry->print_fn = print_fn;
	entry->destroy_fn = destroy_fn;

	if (!entries.init_done) {
		TAILQ_INIT(&entries.w);
		entries.init_done = true;
	}

	TAILQ_INSERT_TAIL(&entries.w, entry, w);
}

void work_print_work(work_t work, const char *queue)
{
	work_priv_t *priv = (work_priv_t *)work;

	priv->entry->print_fn(queue, &priv->stats);
}

void work_destroy_work(work_t work)
{
	work_priv_t *priv = (work_priv_t *)work;

	priv->entry->destroy_fn(priv->data);
	free(priv);
}
