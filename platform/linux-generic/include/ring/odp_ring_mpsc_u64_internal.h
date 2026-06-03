/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef ODP_RING_MPSC_U64_INTERNAL_H_
#define ODP_RING_MPSC_U64_INTERNAL_H_

#include <ring/odp_ring_common.h>

#undef _ODP_RING_TYPE
#define _ODP_RING_TYPE _ODP_RING_TYPE_U64

#undef _ODP_RING_SYNC
#define _ODP_RING_SYNC _ODP_RING_SYNC_MPSC

#include <ring/odp_ring_mpmc_internal.h>

#endif
