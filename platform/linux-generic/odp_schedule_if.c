/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp/autoheader_internal.h>

#include <odp/api/hints.h>

#include <odp/api/plat/schedule_inline_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp_schedule_if.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>

#include <stdlib.h>
#include <string.h>

/* Enable visibility to inline headers */
#include <odp/visibility_begin.h>

const _odp_schedule_api_fn_t *_odp_sched_api;

int _odp_schedule_configured(void)
{
	return odp_global_rw->schedule_configured;
}

#include <odp/visibility_end.h>

extern const schedule_fn_t _odp_schedule_sp_fn;
extern schedule_fn_t _odp_schedule_basic_fn;
const schedule_fn_t *_odp_sched_fn;
int _odp_sched_id;

int odp_schedule_capability(odp_schedule_capability_t *capa)
{
	return _odp_sched_api->schedule_capability(capa);
}

void odp_schedule_config_init(odp_schedule_config_t *config)
{
	memset(config, 0, sizeof(*config));

	_odp_sched_api->schedule_config_init(config);
}

int odp_schedule_config(const odp_schedule_config_t *config)
{
	int ret;
	odp_schedule_config_t defconfig;

	if (odp_global_rw->schedule_configured) {
		_ODP_ERR("Scheduler has been configured already\n");
		return -1;
	}

	if (!config) {
		odp_schedule_config_init(&defconfig);
		config = &defconfig;
	}

	ret = _odp_sched_api->schedule_config(config);

	if (ret >= 0)
		odp_global_rw->schedule_configured = 1;

	return ret;
}

int odp_schedule_min_prio(void)
{
	return _odp_sched_api->schedule_min_prio();
}

int odp_schedule_max_prio(void)
{
	return _odp_sched_api->schedule_max_prio();
}

int odp_schedule_default_prio(void)
{
	return _odp_sched_api->schedule_default_prio();
}

int odp_schedule_num_prio(void)
{
	return _odp_sched_api->schedule_num_prio();
}

odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask)
{
	return _odp_sched_api->schedule_group_create(name, mask);
}

void odp_schedule_group_param_init(odp_schedule_group_param_t *param)
{
	memset(param, 0, sizeof(*param));
}

odp_schedule_group_t odp_schedule_group_create_2(const char *name,
						 const odp_thrmask_t *mask,
						 const odp_schedule_group_param_t *param)
{
	return _odp_sched_api->schedule_group_create_2(name, mask, param);
}

int odp_schedule_group_destroy(odp_schedule_group_t group)
{
	return _odp_sched_api->schedule_group_destroy(group);
}

odp_schedule_group_t odp_schedule_group_lookup(const char *name)
{
	return _odp_sched_api->schedule_group_lookup(name);
}

int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask)
{
	return _odp_sched_api->schedule_group_join(group, mask);
}

int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask)
{
	return _odp_sched_api->schedule_group_leave(group, mask);
}

int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask)
{
	return _odp_sched_api->schedule_group_thrmask(group, thrmask);
}

int odp_schedule_group_info(odp_schedule_group_t group,
			    odp_schedule_group_info_t *info)
{
	return _odp_sched_api->schedule_group_info(group, info);
}

uint64_t odp_schedule_group_to_u64(odp_schedule_group_t group)
{
	return _odp_pri(group);
}

void odp_schedule_print(void)
{
	_odp_sched_api->schedule_print();
}

int _odp_schedule_init_global(void)
{
	const char *sched = getenv("ODP_SCHEDULER");

	if (sched == NULL || !strcmp(sched, "default"))
		sched = _ODP_SCHEDULE_DEFAULT;

	_ODP_PRINT("Using scheduler '%s'\n", sched);

	if (!strcmp(sched, "basic")) {
		_odp_sched_id = _ODP_SCHED_ID_BASIC;
		_odp_sched_fn = &_odp_schedule_basic_fn;
	} else if (!strcmp(sched, "sp")) {
		_odp_sched_id = _ODP_SCHED_ID_SP;
		_odp_sched_fn = &_odp_schedule_sp_fn;
	} else {
		_ODP_ABORT("Unknown scheduler specified via ODP_SCHEDULER\n");
		return -1;
	}

	if (_odp_sched_fn->init_global())
		return -1;

	_odp_sched_api = _odp_sched_fn->sched_api();

	return 0;
}

int _odp_schedule_term_global(void)
{
	return _odp_sched_fn->term_global();
}
