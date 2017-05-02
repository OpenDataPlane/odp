/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>
#include <odp/api/shared_memory.h>

#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_pool_internal.h>

typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	ipsec_ctx_t *ctx;
} ipsec_result_hdr_t;

typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;

	odp_ipsec_status_t status;
} ipsec_status_hdr_t;

static odp_pool_t ipsec_result_pool = ODP_POOL_INVALID;
static odp_pool_t ipsec_status_pool = ODP_POOL_INVALID;

#define IPSEC_EVENTS_POOL_BUF_COUNT 1024

int _odp_ipsec_events_init_global(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.buf.size  = sizeof(ipsec_result_hdr_t);
	param.buf.align = 0;
	param.buf.num   = IPSEC_EVENTS_POOL_BUF_COUNT;
	param.type      = ODP_POOL_BUFFER;

	ipsec_result_pool = odp_pool_create("ipsec_result_pool", &param);
	if (ODP_POOL_INVALID == ipsec_result_pool) {
		ODP_ERR("Error: result pool create failed.\n");
		goto err_result;
	}

	param.buf.size  = sizeof(ipsec_status_hdr_t);
	param.buf.align = 0;
	param.buf.num   = IPSEC_EVENTS_POOL_BUF_COUNT;
	param.type      = ODP_POOL_BUFFER;

	ipsec_status_pool = odp_pool_create("ipsec_status_pool", &param);
	if (ODP_POOL_INVALID == ipsec_status_pool) {
		ODP_ERR("Error: status pool create failed.\n");
		goto err_status;
	}

	return 0;

err_status:
	(void)odp_pool_destroy(ipsec_result_pool);
err_result:
	return -1;
}

int _odp_ipsec_events_term_global(void)
{
	int ret = 0;
	int rc = 0;

	ret = odp_pool_destroy(ipsec_status_pool);
	if (ret < 0) {
		ODP_ERR("status pool destroy failed");
		rc = -1;
	}

	ret = odp_pool_destroy(ipsec_result_pool);
	if (ret < 0) {
		ODP_ERR("result pool destroy failed");
		rc = -1;
	}

	return rc;
}

ipsec_result_t _odp_ipsec_result_from_event(odp_event_t ev)
{
	ODP_ASSERT(ODP_EVENT_INVALID != ev);
	ODP_ASSERT(ODP_EVENT_IPSEC_RESULT == odp_event_type(ev));

	return (ipsec_result_t)ev;
}

static
odp_event_t ipsec_result_to_event(ipsec_result_t res)
{
	ODP_ASSERT(ODP_IPSEC_RESULT_INVALID != res);

	return (odp_event_t)res;
}

static
ipsec_result_hdr_t *ipsec_result_hdr_from_buf(odp_buffer_t buf)
{
	return (ipsec_result_hdr_t *)(void *)buf_hdl_to_hdr(buf);
}

static
ipsec_result_hdr_t *ipsec_result_hdr(ipsec_result_t res)
{
	odp_buffer_t buf = odp_buffer_from_event(ipsec_result_to_event(res));

	return ipsec_result_hdr_from_buf(buf);
}

static
ipsec_result_t _odp_ipsec_result_alloc(void)
{
	odp_buffer_t buf = odp_buffer_alloc(ipsec_result_pool);

	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_IPSEC_RESULT_INVALID;

	_odp_buffer_event_type_set(buf, ODP_EVENT_IPSEC_RESULT);

	return _odp_ipsec_result_from_event(odp_buffer_to_event(buf));
}

void _odp_ipsec_result_free(ipsec_result_t res)
{
	odp_event_t ev = ipsec_result_to_event(res);
	ipsec_result_hdr_t *res_hdr = ipsec_result_hdr(res);

	_odp_ipsec_ctx_free(res_hdr->ctx);

	odp_buffer_free(odp_buffer_from_event(ev));
}

int _odp_ipsec_result_send(odp_queue_t queue, ipsec_ctx_t *ctx)
{
	ipsec_result_t ipsec_ev;
	ipsec_result_hdr_t *res_hdr;

	ipsec_ev = _odp_ipsec_result_alloc();
	if (odp_unlikely(ODP_IPSEC_RESULT_INVALID == ipsec_ev)) {
		_odp_ipsec_ctx_free(ctx);
		return -1;
	}

	res_hdr = ipsec_result_hdr(ipsec_ev);
	res_hdr->ctx = ctx;

	if (odp_queue_enq(queue, ipsec_result_to_event(ipsec_ev))) {
		_odp_ipsec_result_free(ipsec_ev);
		_odp_ipsec_ctx_free(ctx);
		return -1;
	}

	return 0;
}

int odp_ipsec_result(odp_ipsec_op_result_t *result, odp_event_t event)
{
	ipsec_result_t ipsec_ev;
	ipsec_result_hdr_t *res_hdr;

	ODP_ASSERT(ODP_EVENT_INVALID != event);

	ipsec_ev = _odp_ipsec_result_from_event(event);
	ODP_ASSERT(ODP_IPSEC_RESULT_INVALID != ipsec_ev);

	res_hdr = ipsec_result_hdr(ipsec_ev);

	return _odp_ipsec_ctx_result(res_hdr->ctx, result);
}

ipsec_status_t _odp_ipsec_status_from_event(odp_event_t ev)
{
	ODP_ASSERT(ODP_EVENT_INVALID != ev);
	ODP_ASSERT(ODP_EVENT_IPSEC_STATUS == odp_event_type(ev));

	return (ipsec_status_t)ev;
}

static
odp_event_t ipsec_status_to_event(ipsec_status_t status)
{
	ODP_ASSERT(ODP_IPSEC_STATUS_INVALID != status);

	return (odp_event_t)status;
}

static
ipsec_status_hdr_t *ipsec_status_hdr_from_buf(odp_buffer_t buf)
{
	return (ipsec_status_hdr_t *)(void *)buf_hdl_to_hdr(buf);
}

static
ipsec_status_hdr_t *ipsec_status_hdr(ipsec_status_t status)
{
	odp_buffer_t buf = odp_buffer_from_event(ipsec_status_to_event(status));

	return ipsec_status_hdr_from_buf(buf);
}

static
ipsec_status_t odp_ipsec_status_alloc(void)
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
			   int ret,
			   odp_ipsec_sa_t sa)
{
	ipsec_status_t ipsec_ev = odp_ipsec_status_alloc();
	ipsec_status_hdr_t *status_hdr;

	if (ODP_IPSEC_STATUS_INVALID == ipsec_ev)
		return -1;

	status_hdr = ipsec_status_hdr(ipsec_ev);

	status_hdr->status.id = id;
	status_hdr->status.ret = ret;
	status_hdr->status.sa = sa;

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
