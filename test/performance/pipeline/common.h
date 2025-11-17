/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef COMMON_H_
#define COMMON_H_

#define CLASSIFICATION_DOMAIN "classification"
#define CPUMAP_DOMAIN "cpumap"
#define CRYPTO_DOMAIN "crypto"
#define DMA_DOMAIN "dma"
#define FLOW_DOMAIN "flows"
#define	PKTIO_DOMAIN "pktios"
#define	POOL_DOMAIN "pools"
#define	QUEUE_DOMAIN "queues"
#define SCHED_DOMAIN "scheduler"
#define STASH_DOMAIN "stash"
#define TIMER_DOMAIN "timers"
#define	WORKER_DOMAIN "workers"

#define CRIT_PRIO 101
#define HIGH_PRIO (CRIT_PRIO + 1)
#define MED_PRIO (HIGH_PRIO + 1)
#define LOW_PRIO (MED_PRIO + 1)

#endif
