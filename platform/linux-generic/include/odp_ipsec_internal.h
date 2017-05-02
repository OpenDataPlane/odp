/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP internal IPsec routines
 */

#ifndef ODP_IPSEC_INTERNAL_H_
#define ODP_IPSEC_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp/api/ipsec.h>

/** @ingroup odp_ipsec
 *  @{
 */

typedef ODP_HANDLE_T(ipsec_result_t);

#define ODP_IPSEC_RESULT_INVALID \
	_odp_cast_scalar(ipsec_result_t, 0xffffffff)

typedef ODP_HANDLE_T(ipsec_status_t);

#define ODP_IPSEC_STATUS_INVALID \
	_odp_cast_scalar(ipsec_status_t, 0xffffffff)

typedef struct ipsec_ctx_s ipsec_ctx_t;

/**
 * @internal Free IPsec context
 *
 * Frees the IPsec context into the pool it was allocated from.
 *
 * @param ctx		IPsec context
 */
void _odp_ipsec_ctx_free(ipsec_ctx_t *ctx);

/**
 * @internal Process context filling operation result information
 *
 * Processes IPsec operation context related to completed operation, extracting
 * operation result information. This function may update context provided via
 * pointer to opaque context pointer.
 *
 * @param         ctx     IPsec context pointer.
 * @param[out]    result  Pointer to operation result for output. May be
 *                        NULL, if application is interested only on the
 *                        number of packets.
 *
 * @return Number of packets remaining in the event.
 * @retval <0     On failure
 */
int _odp_ipsec_ctx_result(ipsec_ctx_t *ctx, odp_ipsec_op_result_t *result);

/**
 * @internal Get ipsec_result handle from event
 *
 * Converts an ODP_EVENT_IPSEC_RESULT type event to an IPsec result event.
 *
 * @param ev   Event handle
 *
 * @return IPsec result handle
 *
 * @see odp_event_type()
 */
ipsec_result_t _odp_ipsec_result_from_event(odp_event_t ev);

/**
 * @internal Free IPsec result event
 *
 * Frees the ipsec_result into the ipsec_result pool it was allocated from.
 *
 * @param res           IPsec result handle
 */
void _odp_ipsec_result_free(ipsec_result_t res);

/**
 * @internal Send ODP_IPSEC_RESULT event
 *
 * Sends the ipsec_result event using provided information
 *
 * @param queue         destination queue
 * @param ctx           IPsec context for the operation
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_ipsec_result_send(odp_queue_t queue, ipsec_ctx_t *ctx);

/**
 * @internal Get ipsec_status handle from event
 *
 * Converts an ODP_EVENT_IPSEC_STATUS type event to an IPsec status event.
 *
 * @param ev   Event handle
 *
 * @return IPsec status handle
 *
 * @see odp_event_type()
 */
ipsec_status_t _odp_ipsec_status_from_event(odp_event_t ev);

/**
 * @internal Free IPsec status event
 *
 * Frees the ipsec_status into the ipsec_status pool it was allocated from.
 *
 * @param res           IPsec status handle
 */
void _odp_ipsec_status_free(ipsec_status_t status);

/**
 * @internal Send ODP_IPSEC_STATUS event
 *
 * Sends the ipsec_status event using provided information
 *
 * @param queue         destination queue
 * @param id            status id
 * @param ret           status value
 * @param sa            SA respective to the operation
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_ipsec_status_send(odp_queue_t queue,
			   odp_ipsec_status_id_t id,
			   int ret,
			   odp_ipsec_sa_t sa);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
