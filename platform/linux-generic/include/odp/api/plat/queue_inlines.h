/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2023-2025 Nokia
 */

#ifndef ODP_PLAT_QUEUE_INLINES_H_
#define ODP_PLAT_QUEUE_INLINES_H_

#include <string.h>

#include <odp/api/hints.h>

#include <odp/api/plat/event_validation_external.h>
#include <odp/api/plat/queue_inline_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_queue_api_fn_t *_odp_queue_api;

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_queue_context   __odp_queue_context
	#define odp_queue_enq       __odp_queue_enq
	#define odp_queue_enq_multi __odp_queue_enq_multi
	#define odp_queue_enq_aggr  __odp_queue_enq_aggr
	#define odp_aggr_enq_param_init __odp_aggr_enq_param_init
	#define odp_queue_deq       __odp_queue_deq
	#define odp_queue_deq_multi __odp_queue_deq_multi
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE void *odp_queue_context(odp_queue_t handle)
{
	void *context;
	void *qentry = (void *)handle;

	context = _odp_qentry_field(qentry, void *, context);

	return context;
}

_ODP_INLINE int odp_queue_enq(odp_queue_t queue, odp_event_t ev)
{
	if (odp_unlikely(_odp_event_validate(ev, _ODP_EV_QUEUE_ENQ)))
		return -1;

	return _odp_queue_api->queue_enq(queue, ev);
}

_ODP_INLINE int odp_queue_enq_multi(odp_queue_t queue,
				    const odp_event_t events[], int num)
{
	if (odp_unlikely(_odp_event_validate_multi(events, num, _ODP_EV_QUEUE_ENQ_MULTI)))
		return -1;

	return _odp_queue_api->queue_enq_multi(queue, events, num);
}

_ODP_INLINE int odp_queue_enq_aggr(odp_queue_t queue, odp_event_t ev,
				   const odp_aggr_enq_param_t *param ODP_UNUSED)
{
	return odp_queue_enq(queue, ev);
}

_ODP_INLINE void odp_aggr_enq_param_init(odp_aggr_enq_param_t *param)
{
	memset(param, 0, sizeof(*param));
}

_ODP_INLINE odp_event_t odp_queue_deq(odp_queue_t queue)
{
	return _odp_queue_api->queue_deq(queue);
}

_ODP_INLINE int odp_queue_deq_multi(odp_queue_t queue,
				    odp_event_t events[], int num)
{
	return _odp_queue_api->queue_deq_multi(queue, events, num);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
