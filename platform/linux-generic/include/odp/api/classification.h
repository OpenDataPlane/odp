/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_PLAT_CLASSIFICATION_H_
#define ODP_PLAT_CLASSIFICATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/pool_types.h>
#include <odp/api/plat/classification_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/queue_types.h>

/** @ingroup odp_classification
 *  @{
 */

/* REMOVE THESE FROM API SPEC. Typedefs needed only for suppressing Doxygen
 * warning. */
typedef void odp_flowsig_t;
typedef void odp_cos_flow_set_t;

/**
 * @}
 */

#include <odp/api/spec/classification.h>

#ifdef __cplusplus
}
#endif

#endif
