/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_PKTIO_H_
#define _ODP_TEST_PKTIO_H_

#include <odp_cunit_common.h>

/* test functions: */
void pktio_test_plain_queue(void);
void pktio_test_plain_multi(void);
void pktio_test_sched_queue(void);
void pktio_test_sched_multi(void);
void pktio_test_recv(void);
void pktio_test_recv_multi(void);
void pktio_test_recv_queue(void);
void pktio_test_recv_tmo(void);
void pktio_test_recv_mq_tmo(void);
void pktio_test_recv_mtu(void);
void pktio_test_mtu(void);
void pktio_test_promisc(void);
void pktio_test_mac(void);
void pktio_test_inq_remdef(void);
void pktio_test_open(void);
void pktio_test_lookup(void);
void pktio_test_index(void);
void pktio_test_info(void);
void pktio_test_inq(void);
void pktio_test_pktio_config(void);
void pktio_test_pktin_queue_config_direct(void);
void pktio_test_pktin_queue_config_sched(void);
void pktio_test_pktin_queue_config_queue(void);
void pktio_test_pktout_queue_config(void);
void pktio_test_start_stop(void);
int pktio_check_send_failure(void);
void pktio_test_send_failure(void);
void pktio_test_recv_on_wonly(void);
void pktio_test_send_on_ronly(void);
void pktio_test_plain_multi_event(void);
void pktio_test_sched_multi_event(void);
void pktio_test_recv_multi_event(void);
int pktio_check_statistics_counters(void);
void pktio_test_statistics_counters(void);
int pktio_check_pktin_ts(void);
void pktio_test_pktin_ts(void);

/* test arrays: */
extern odp_testinfo_t pktio_suite[];

/* test array init/term functions: */
int pktio_suite_term(void);
int pktio_suite_init_segmented(void);
int pktio_suite_init_unsegmented(void);

/* test registry: */
extern odp_suiteinfo_t pktio_suites[];

/* main test program: */
int pktio_main(int argc, char *argv[]);

#endif
