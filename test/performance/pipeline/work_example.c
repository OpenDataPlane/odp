/*
 * Example work for an external work library. Not built as part of the tester, see the "External
 * work libraries" section of README.md for how to build and load this.
 */

#include <odp_pipeline_config.h>
#include <odp_pipeline_work.h>

#include <odp/helper/odph_api.h>

#include <stdio.h>

#define WORK_EXAMPLE "example"

/*
 * Count the events passing through and enqueue them to the queue named in the first work
 * parameter.
 */
static int work_example(uintptr_t data, odp_event_t ev[], int num, odp_pl_work_stats_t *stats)
{
	int ret = odp_queue_enq_multi((odp_queue_t)data, ev, num);

	if (ret < 0)
		ret = 0;

	stats->data1 += ret;

	return ret;
}

static void work_example_init(const odp_pl_work_param_t *param, odp_pl_work_init_t *init)
{
	const char *queue;

	if (param->param == NULL || config_setting_length(param->param) != 1)
		ODPH_ABORT("Expected one parameter: (output queue)\n");

	queue = config_setting_get_string_elem(param->param, 0);

	if (queue == NULL)
		ODPH_ABORT("Parameter 0 is not a string\n");

	init->fn = work_example;
	init->data = odp_pl_config_parser_get(ODP_PL_QUEUE_DOMAIN, queue);
}

static void work_example_print(const char *queue, const odp_pl_work_stats_t *stats)
{
	printf("\n%s:\n"
	       "  work:             %s\n"
	       "  events forwarded: %" PRIu64 "\n", queue, WORK_EXAMPLE, stats->data1);
}

static void work_example_destroy(uintptr_t data ODP_UNUSED)
{
}

ODP_PL_WORK_AUTOREGISTER(WORK_EXAMPLE, work_example_init, work_example_print,
			 work_example_destroy)
