/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

/**
 * @file
 *
 * ODP event validation
 *
 * @warning These definitions are not part of ODP API, they are for
 * implementation internal use only.
 */

#ifndef ODP_EVENT_VALIDATION_EXTERNAL_H_
#define ODP_EVENT_VALIDATION_EXTERNAL_H_

#include <odp/autoheader_external.h>

#include <odp/api/buffer_types.h>
#include <odp/api/event_types.h>
#include <odp/api/hints.h>
#include <odp/api/packet_types.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifdef __cplusplus
extern "C" {
#endif

/** Enumerations for identifying ODP API functions */
typedef enum {
	_ODP_EV_BUFFER_FREE = 0,
	_ODP_EV_BUFFER_FREE_MULTI,
	_ODP_EV_BUFFER_IS_VALID,
	_ODP_EV_EVENT_FREE,
	_ODP_EV_EVENT_FREE_MULTI,
	_ODP_EV_EVENT_FREE_SP,
	_ODP_EV_EVENT_IS_VALID,
	_ODP_EV_PACKET_FREE,
	_ODP_EV_PACKET_FREE_MULTI,
	_ODP_EV_PACKET_FREE_SP,
	_ODP_EV_PACKET_IS_VALID,
	_ODP_EV_QUEUE_ENQ,
	_ODP_EV_QUEUE_ENQ_MULTI,
	_ODP_EV_MAX
} _odp_ev_id_t;

/* Implementation internal event validation functions */
#if _ODP_EVENT_VALIDATION

int _odp_event_validate(odp_event_t event, _odp_ev_id_t id);

int _odp_event_validate_multi(const odp_event_t event[], int num, _odp_ev_id_t id);

int _odp_buffer_validate(odp_buffer_t buf, _odp_ev_id_t ev_id);

int _odp_buffer_validate_multi(const odp_buffer_t buf[], int num, _odp_ev_id_t ev_id);

int _odp_packet_validate(odp_packet_t pkt, _odp_ev_id_t ev_id);

int _odp_packet_validate_multi(const odp_packet_t pkt[], int num, _odp_ev_id_t ev_id);

#else

static inline int _odp_event_validate(odp_event_t event ODP_UNUSED, _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

static inline int _odp_event_validate_multi(const odp_event_t event[] ODP_UNUSED,
					    int num ODP_UNUSED,
					    _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

static inline int _odp_buffer_validate(odp_buffer_t buf ODP_UNUSED, _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

static inline int _odp_buffer_validate_multi(const odp_buffer_t buf[] ODP_UNUSED,
					     int num ODP_UNUSED,
					     _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

static inline int _odp_packet_validate(odp_packet_t pkt ODP_UNUSED, _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

static inline int _odp_packet_validate_multi(const odp_packet_t pkt[] ODP_UNUSED,
					     int num ODP_UNUSED,
					     _odp_ev_id_t ev_id ODP_UNUSED)
{
	return 0;
}

#endif /* _ODP_EVENT_VALIDATION */

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif
