/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP forward typedefs - implementation internal
 *
 * This needs to be a separate file because it is needed by both
 * odp_queue_internal.h and odp_queue_lf.h and clang prohibits forward
 * "redefining" typedefs. Note that this file can be extended with additional
 * forward typedefs as needed.
 */

#ifndef ODP_FORWARD_TYPEDEFS_INTERNAL_H_
#define ODP_FORWARD_TYPEDEFS_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct queue_entry_s queue_entry_t;

#ifdef __cplusplus
}
#endif

#endif
