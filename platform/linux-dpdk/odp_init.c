/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <odp/api/cpu.h>
#include <odp/init.h>
#include <odp_internal.h>
#include <odp/debug.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>
#include <odp/system_info.h>
#include <odp/cpumask.h>
#include <unistd.h>
#include <rte_string_fns.h>

#define PMD_EXT(drv)  extern void devinitfn_##drv(void);
PMD_EXT(cryptodev_aesni_mb_pmd_drv)
PMD_EXT(pmd_qat_drv)
PMD_EXT(pmd_af_packet_drv)
PMD_EXT(rte_bnx2x_driver)
PMD_EXT(rte_bnx2xvf_driver)
PMD_EXT(bond_drv)
PMD_EXT(rte_cxgbe_driver)
PMD_EXT(em_pmd_drv)
PMD_EXT(pmd_igb_drv)
PMD_EXT(pmd_igbvf_drv)
PMD_EXT(rte_enic_driver)
PMD_EXT(rte_fm10k_driver)
PMD_EXT(rte_i40e_driver)
PMD_EXT(rte_i40evf_driver)
PMD_EXT(rte_ixgbe_driver)
PMD_EXT(rte_ixgbevf_driver)
PMD_EXT(rte_mlx4_driver)
PMD_EXT(rte_mlx5_driver)
PMD_EXT(pmd_mpipe_xgbe_drv)
PMD_EXT(pmd_mpipe_gbe_drv)
PMD_EXT(rte_nfp_net_driver)
PMD_EXT(pmd_null_drv)
PMD_EXT(pmd_pcap_drv)
PMD_EXT(pmd_ring_drv)
PMD_EXT(pmd_szedata2_drv)
PMD_EXT(rte_virtio_driver)
PMD_EXT(rte_vmxnet3_driver)
PMD_EXT(pmd_xenvirt_drv)

/*
 * This function is not called from anywhere, it's only purpose is to make sure
 * that if ODP and DPDK are statically linked to an application, the GCC
 * constuctors of the PMDs are linked as well. Otherwise the linker would omit
 * them. It's not an issue with dynamic linking. */
void refer_constructors(void);
void refer_constructors(void) {
#ifdef RTE_LIBRTE_PMD_AESNI_MB
	devinitfn_cryptodev_aesni_mb_pmd_drv();
#endif
#ifdef RTE_LIBRTE_PMD_QAT
	devinitfn_pmd_qat_drv();
#endif
#ifdef RTE_LIBRTE_PMD_AF_PACKET
	devinitfn_pmd_af_packet_drv();
#endif
#ifdef RTE_LIBRTE_BNX2X_PMD
	devinitfn_rte_bnx2x_driver();
	devinitfn_rte_bnx2xvf_driver();
#endif
#ifdef RTE_LIBRTE_PMD_BOND
	devinitfn_bond_drv();
#endif
#ifdef RTE_LIBRTE_CXGBE_PMD
	devinitfn_rte_cxgbe_driver();
#endif
#ifdef RTE_LIBRTE_EM_PMD
	devinitfn_em_pmd_drv();
#endif
#ifdef RTE_LIBRTE_IGB_PMD
	devinitfn_pmd_igb_drv();
	devinitfn_pmd_igbvf_drv();
#endif
#ifdef RTE_LIBRTE_ENIC_PMD
	devinitfn_rte_enic_driver();
#endif
#ifdef RTE_LIBRTE_FM10K_PMD
	devinitfn_rte_fm10k_driver();
#endif
#ifdef RTE_LIBRTE_I40E_PMD
	devinitfn_rte_i40e_driver();
	devinitfn_rte_i40evf_driver();
#endif
#ifdef RTE_LIBRTE_IXGBE_PMD
	devinitfn_rte_ixgbe_driver();
	devinitfn_rte_ixgbevf_driver();
#endif
#ifdef RTE_LIBRTE_MLX4_PMD
	devinitfn_rte_mlx4_driver();
#endif
#ifdef RTE_LIBRTE_MLX5_PMD
	devinitfn_rte_mlx5_driver();
#endif
#ifdef RTE_LIBRTE_MPIPE_PMD
	devinitfn_pmd_mpipe_xgbe_drv()
	devinitfn_pmd_mpipe_gbe_drv()
#endif
#ifdef RTE_LIBRTE_NFP_PMD
	devinitfn_rte_nfp_net_driver();
#endif
#ifdef RTE_LIBRTE_PMD_NULL
	devinitfn_pmd_null_drv();
#endif
#ifdef RTE_LIBRTE_PMD_PCAP
	devinitfn_pmd_pcap_drv();
#endif
#ifdef RTE_LIBRTE_PMD_RING
	devinitfn_pmd_ring_drv();
#endif
#ifdef RTE_LIBRTE_PMD_SZEDATA2
	devinitfn_pmd_szedata2_drv();
#endif
#ifdef RTE_LIBRTE_VIRTIO_PMD
	devinitfn_rte_virtio_driver();
#endif
#ifdef RTE_LIBRTE_VMXNET3_PMD
	devinitfn_rte_vmxnet3_driver();
#endif
#ifdef RTE_LIBRTE_PMD_XENVIRT
	devinitfn_pmd_xenvirt_drv();
#endif
}

static void print_dpdk_env_help(void)
{
	char prgname[] = "odpdpdk";
	char help_str[] = "--help";
	char *dpdk_argv[] = {prgname, help_str};
	int save_optind, dpdk_argc = 2;

	ODP_ERR("Neither (char *)platform_params were provided to "
		"odp_init_global(),\n");
	ODP_ERR("nor ODP_PLATFORM_PARAMS environment variable were "
		"specified.\n");
	ODP_ERR("A string of DPDK command line arguments should be provided");
	ODP_ERR("Example: export ODP_PLATFORM_PARAMS=\"-n 4 --no-huge\"\n");
	ODP_ERR("Note: -c argument substitutes automatically from odp coremask\n");
	save_optind = optind;
	optind = 1;
	rte_eal_init(dpdk_argc, dpdk_argv);
	optind = save_optind;
}


int odp_init_dpdk(const char *cmdline)
{
	char **dpdk_argv;
	int dpdk_argc;
	char *full_cmdline;
	int i, cmdlen;
	odp_cpumask_t mask;
	char mask_str[ODP_CPUMASK_STR_SIZE];
	int32_t masklen;
	cpu_set_t original_cpuset;

	if (cmdline == NULL) {
		cmdline = getenv("ODP_PLATFORM_PARAMS");
		if (cmdline == NULL) {
			print_dpdk_env_help();
			return -1;
		}
	}

	CPU_ZERO(&original_cpuset);
	i = pthread_getaffinity_np(pthread_self(),
				   sizeof(original_cpuset), &original_cpuset);
	if (i != 0) {
		ODP_ERR("Failed to read thread affinity: %d\n", i);
		return -1;
	}

	odp_cpumask_zero(&mask);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &original_cpuset)) {
			odp_cpumask_set(&mask, i);
			break;
		}
	}
	masklen = odp_cpumask_to_str(&mask, mask_str, ODP_CPUMASK_STR_SIZE);

	if (masklen < 0) {
		ODP_ERR("CPU mask error: d\n", masklen);
		return -1;
	}

	/* masklen includes the terminating null as well */
	full_cmdline = calloc(1, strlen("odpdpdk -c ") + masklen +
			      strlen(" ") + strlen(cmdline));

	/* first argument is facility log, simply bind it to odpdpdk for now.*/
	cmdlen = sprintf(full_cmdline, "odpdpdk -c %s %s", mask_str, cmdline);

	for (i = 0, dpdk_argc = 1; i < cmdlen; ++i) {
		if (isspace(full_cmdline[i])) {
			++dpdk_argc;
		}
	}
	dpdk_argv = malloc(dpdk_argc * sizeof(char *));

	dpdk_argc = rte_strsplit(full_cmdline, strlen(full_cmdline), dpdk_argv,
				 dpdk_argc, ' ');
	for (i = 0; i < dpdk_argc; ++i)
		ODP_DBG("arg[%d]: %s\n", i, dpdk_argv[i]);
	fflush(stdout);

	i = rte_eal_init(dpdk_argc, dpdk_argv);
	free(dpdk_argv);
	free(full_cmdline);
	if (i < 0) {
		ODP_ERR("Cannot init the Intel DPDK EAL!\n");
		return -1;
	} else if (i != dpdk_argc) {
		ODP_DBG("Some DPDK args were not processed!\n");
		ODP_DBG("Passed: %d Consumed %d\n", dpdk_argc, i);
	}
	ODP_DBG("rte_eal_init OK\n");

	i = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
				   &original_cpuset);
	if (i)
		ODP_ERR("Failed to reset thread affinity: %d\n", i);

	return 0;
}

struct odp_global_data_s odp_global_data;

int odp_init_global(const odp_init_t *params,
		    const odp_platform_init_t *platform_params)
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

	if (odp_init_dpdk((const char *)platform_params)) {
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

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		return -1;
	}

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		return -1;
	}

#if 0 /* for now classification is disabled */
	if (odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		return -1;
	}
#endif

	return 0;
}

int odp_term_global(void)
{
	int rc = 0;

#if 0 /* for now classification is disabled */
	if (odp_classification_term_global()) {
		ODP_ERR("ODP classificatio term failed.\n");
		rc = -1;
	}
#endif

	if (odp_crypto_term_global()) {
		ODP_ERR("ODP crypto term failed.\n");
		rc = -1;
	}

	if (odp_schedule_term_global()) {
		ODP_ERR("ODP schedule term failed.\n");
		rc = -1;
	}

	if (odp_pktio_term_global()) {
		ODP_ERR("ODP pktio term failed.\n");
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

int odp_init_local(odp_thread_type_t thr_type)
{
	if (odp_shm_init_local()) {
		ODP_ERR("ODP shm local init failed.\n");
		return -1;
	}

	if (odp_thread_init_local(thr_type)) {
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
