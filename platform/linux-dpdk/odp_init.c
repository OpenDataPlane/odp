/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/cpu.h>
#include <odp/init.h>
#include <odp_internal.h>
#include <odp/debug.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>
#include <odp/system_info.h>


static int parse_dpdk_args(char *args, int *dst_argc, char ***dst_argv) {
	char *buf = strdup(args);
	int num = 1;
	char *delim;
	char **argv = calloc(num, sizeof(char *));

	argv[0] = buf;

	while (1) {
		delim = strchr(argv[num - 1], ' ');
		if (delim == NULL)
			break;
		argv = realloc(argv, (num + 1) * sizeof(char *));
		argv[num] = delim + 1;
		*delim = 0;
		num++;
	}

	*dst_argc = num;
	*dst_argv = argv;

	return num;
}


static void print_dpdk_env_help(void)
{
	ODP_ERR("Example: export ODP_PLATFORM_PARAMS=\"-n NUM -- -p PORT\"\n");
	ODP_ERR("Refer to DPDK documentation for parameters specified before and after --\n");
}


int odp_init_dpdk(void)
{
	char **dpdk_argv;
	int dpdk_argc;
	char *env;
	char *new_env;
	int numargs;
	int core_mask, i;

	env = getenv("ODP_PLATFORM_PARAMS");
	if (env == NULL) {
		print_dpdk_env_help();
		ODP_ERR("ODP_PLATFORM_PARAMS has to be exported");
		return -1;
	}

	for (i = 0, core_mask = 0; i <  odp_cpu_count(); i++)
		core_mask += (0x1 << i);

	new_env = calloc(1, strlen(env) + strlen("odpdpdk -c ") +
			sizeof(core_mask) + 1);

	/* first argument is facility log, simple bind it to odpdpdk for now.*/
	sprintf(new_env, "odpdpdk -c %x %s", core_mask, env);

	numargs = parse_dpdk_args(new_env, &dpdk_argc, &dpdk_argv);
	while (numargs) {
		int i = dpdk_argc - numargs;
		ODP_DBG("arg[%d]: %s\n", i, dpdk_argv[i]);
		numargs--;
	};
	fflush(stdout);
	free(new_env);

	if (rte_eal_init(dpdk_argc, dpdk_argv) < 0) {
		ODP_ERR("Cannot init the Intel DPDK EAL!");
		return -1;
	}
	ODP_DBG("rte_eal_init OK\n");

	if (rte_eal_pci_probe() < 0) {
		ODP_ERR("Cannot probe PCI\n");
		return -1;
	}

	return 0;
}

struct odp_global_data_s odp_global_data;

int odp_init_global(odp_init_t *params  ODP_UNUSED,
		    odp_platform_init_t *platform_params ODP_UNUSED)
{
	odp_global_data.log_fn = odp_override_log;
	odp_global_data.abort_fn = odp_override_abort;

	if (params != NULL) {
		if (params->log_fn != NULL)
			odp_global_data.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_data.abort_fn = params->abort_fn;
	}

	odp_system_info_init();

	if (odp_init_dpdk()) {
		ODP_ERR("ODP dpdk init failed.\n");
		return -1;
	}

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		return -1;
	}

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		return -1;
	}

	if (odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		return -1;
	}

#if 0 /* for now timer is disabled */
	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		return -1;
	}
#endif

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_global(void)
{
	int rc = 0;

	if (odp_crypto_term_global()) {
		ODP_ERR("ODP crypto term failed.\n");
		rc = -1;
	}

	if (odp_schedule_term_global()) {
		ODP_ERR("ODP schedule term failed.\n");
		rc = -1;
	}

	if (odp_queue_term_global()) {
		ODP_ERR("ODP queue term failed.\n");
		rc = -1;
	}

	if (odp_thread_term_global()) {
		ODP_ERR("ODP thread term failed.\n");
		rc = -1;
	}

	if (odp_shm_term_global()) {
		ODP_ERR("ODP shm term failed.\n");
		rc = -1;
	}

	return rc;
}

int odp_init_local(void)
{
	if (odp_thread_init_local()) {
		ODP_ERR("ODP thread local init failed.\n");
		return -1;
	}

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		return -1;
	}

	if (odp_schedule_init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_local(void)
{
	int rc = 0;
	int rc_thd = 0;

	if (odp_schedule_term_local()) {
		ODP_ERR("ODP schedule local term failed.\n");
		rc = -1;
	}

	rc_thd = odp_thread_term_local();
	if (rc_thd < 0) {
		ODP_ERR("ODP thread local term failed.\n");
		rc = -1;
	} else {
		if (!rc)
			rc = rc_thd;
	}

	return rc;
}
