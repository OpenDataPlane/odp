/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_CLASSIFICATION_H_
#define _ODP_TEST_CLASSIFICATION_H_

#include <odp_cunit_common.h>

#define SHM_PKT_NUM_BUFS        32
#define SHM_PKT_BUF_SIZE        1024

/* Config values for Default CoS */
#define TEST_DEFAULT		1
#define	CLS_DEFAULT		0
#define CLS_DEFAULT_SADDR	"10.0.0.1/32"
#define CLS_DEFAULT_DADDR	"10.0.0.100/32"
#define CLS_DEFAULT_SPORT	1024
#define CLS_DEFAULT_DPORT	2048
#define CLS_DEFAULT_DMAC	{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
#define CLS_DEFAULT_SMAC	{0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
#define CLS_MAGIC_VAL		0xdeadbeef

/* Config values for Drop CoS */
#define TEST_DROP		1
#define CLS_DROP		6
#define CLS_DROP_PORT		4001

/* Config values for Error CoS */
#define TEST_ERROR		1
#define CLS_ERROR		1

/* Config values for PMR_CHAIN */
#define TEST_PMR_CHAIN		1
#define CLS_PMR_CHAIN_SRC	2
#define CLS_PMR_CHAIN_DST	3
#define CLS_PMR_CHAIN_SADDR	"10.0.0.5/32"
#define CLS_PMR_CHAIN_PORT	3000

/* Config values for PMR */
#define TEST_PMR		1
#define CLS_PMR			4
#define CLS_PMR_PORT		4000

/* Config values for PMR SET */
#define TEST_PMR_SET		1
#define CLS_PMR_SET		5
#define CLS_PMR_SET_SADDR	"10.0.0.6/32"
#define CLS_PMR_SET_PORT	5000

/* Config values for CoS L2 Priority */
#define TEST_L2_QOS		1
#define CLS_L2_QOS_0		7
#define CLS_L2_QOS_MAX		5

#define CLS_ENTRIES		(CLS_L2_QOS_0 + CLS_L2_QOS_MAX)

/* Test Packet values */
#define DATA_MAGIC		0x01020304
#define TEST_SEQ_INVALID	((uint32_t)~0)

/* Test packet Time-to-live */
#define DEFAULT_TTL              128

/* Test packet default DSCP value */
#define LOW_DROP_PRECEDENCE      0x02
#define MEDIUM_DROP_PRECEDENCE   0x04
#define HIGH_DROP_PRECEDENCE     0x06
#define DROP_PRECEDENCE_MASK     0x06
#define DSCP_CLASS1              0x08
#define DSCP_CLASS2              0x10
#define DSCP_CLASS3              0x18
#define DSCP_CLASS4              0x20
#define DEFAULT_DSCP             (DSCP_CLASS2 | LOW_DROP_PRECEDENCE)

/* Test packet default ECN */
#define DEFAULT_ECN              ODPH_IP_ECN_ECT0

/* Test packet default TOS */
#define DEFAULT_TOS              ((DEFAULT_DSCP << ODPH_IP_TOS_DSCP_SHIFT) | \
					DEFAULT_ECN)

#endif
