/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>
#include <odp/api/shared_memory.h>

#include <odp_init_internal.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_pool_internal.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/queue_inlines.h>

typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	odp_ipsec_status_t status;
} ipsec_status_hdr_t;

static odp_pool_t ipsec_status_pool = ODP_POOL_INVALID;

#define IPSEC_EVENTS_POOL_BUF_COUNT 1024

int _odp_ipsec_events_init_global(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.buf.size  = sizeof(ipsec_status_hdr_t);
	param.buf.align = 0;
	param.buf.num   = IPSEC_EVENTS_POOL_BUF_COUNT;
	param.type      = ODP_POOL_BUFFER;

	ipsec_status_pool = odp_pool_create("_odp_ipsec_status_pool", &param);
	if (ODP_POOL_INVALID == ipsec_status_pool) {
		ODP_ERR("Error: status pool create failed.\n");
		goto err_status;
	}

	return 0;

err_status:
	return -1;
}

int _odp_ipsec_events_term_global(void)
{
	int ret;

	ret = odp_pool_destroy(ipsec_status_pool);
	if (ret < 0) {
		ODP_ERR("status pool destroy failed");
		return -1;
	}

	return 0;
}

ipsec_status_t _odp_ipsec_status_from_event(odp_event_t ev)
{
	ODP_ASSERT(ODP_EVENT_INVALID != ev);
	ODP_ASSERT(ODP_EVENT_IPSEC_STATUS == odp_event_type(ev));

	return (ipsec_status_t)ev;
}

static odp_event_t ipsec_status_to_event(ipsec_status_t status)
{
	ODP_ASSERT(ODP_IPSEC_STATUS_INVALID != status);

	return (odp_event_t)status;
}

static ipsec_status_hdr_t *ipsec_status_hdr_from_buf(odp_buffer_t buf)
{
	return (ipsec_status_hdr_t *)(void *)buf_hdl_to_hdr(buf);
}

static ipsec_status_hdr_t *ipsec_status_hdr(ipsec_status_t status)
{
	odp_buffer_t buf = odp_buffer_from_event(ipsec_status_to_event(status));

	return ipsec_status_hdr_from_buf(buf);
}

static ipsec_status_t odp_ipsec_status_alloc(void)
{
	odp_buffer_t buf = odp_buffer_alloc(ipsec_status_pool);

	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_IPSEC_STATUS_INVALID;

	_odp_buffer_event_type_set(buf, ODP_EVENT_IPSEC_STATUS);

	return _odp_ipsec_status_from_event(odp_buffer_to_event(buf));
}

void _odp_ipsec_status_free(ipsec_status_t status)
{
	odp_event_t ev = ipsec_status_to_event(status);

	odp_buffer_free(odp_buffer_from_event(ev));
}

int _odp_ipsec_status_send(odp_queue_t queue,
			   odp_ipsec_status_id_t id,
			   odp_ipsec_sa_t sa,
			   int result,
			   odp_ipsec_warn_t warn)
{
	ipsec_status_t ipsec_ev = odp_ipsec_status_alloc();
	ipsec_status_hdr_t *status_hdr;

	if (ODP_IPSEC_STATUS_INVALID == ipsec_ev)
		return -1;

	status_hdr = ipsec_status_hdr(ipsec_ev);

	status_hdr->status.id = id;
	status_hdr->status.sa = sa;
	status_hdr->status.result = result;
	status_hdr->status.warn = warn;

	if (odp_queue_enq(queue, ipsec_status_to_event(ipsec_ev))) {
		_odp_ipsec_status_free(ipsec_ev);
		return -1;
	}

	return 0;
}

int odp_ipsec_status(odp_ipsec_status_t *status, odp_event_t event)
{
	ipsec_status_t ipsec_ev;
	ipsec_status_hdr_t *status_hdr;

	if (odp_unlikely(ODP_EVENT_INVALID == event))
		return -1;

	ipsec_ev = _odp_ipsec_status_from_event(event);
	if (odp_unlikely(ODP_IPSEC_STATUS_INVALID == ipsec_ev))
		return -1;

	status_hdr = ipsec_status_hdr(ipsec_ev);

	*status = status_hdr->status;

	return 0;
}
