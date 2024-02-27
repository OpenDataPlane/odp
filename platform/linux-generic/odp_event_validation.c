/* Copyright (c) 2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/atomic.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/shared_memory.h>

#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_event_validation_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <string.h>

#define EVENT_VALIDATION_NONE  0
#define EVENT_VALIDATION_WARN  1
#define EVENT_VALIDATION_ABORT 2

#define EVENT_DATA_PRINT_MAX_LEN 128

typedef struct {
	odp_atomic_u64_t err_count[_ODP_EV_MAX];
	odp_shm_t shm;

} event_validation_global_t;

typedef struct {
	const char *str;
} _odp_ev_info_t;

static event_validation_global_t *_odp_ev_glb;

#if _ODP_EVENT_VALIDATION

/* Table for mapping function IDs to API function names */
static const _odp_ev_info_t ev_info_tbl[] = {
	[_ODP_EV_BUFFER_FREE]       = {.str = "odp_buffer_free()"},
	[_ODP_EV_BUFFER_FREE_MULTI] = {.str = "odp_buffer_free_multi()"},
	[_ODP_EV_BUFFER_IS_VALID]   = {.str = "odp_buffer_is_valid()"},
	[_ODP_EV_EVENT_FREE]        = {.str = "odp_event_free()"},
	[_ODP_EV_EVENT_FREE_MULTI]  = {.str = "odp_event_free_multi()"},
	[_ODP_EV_EVENT_FREE_SP]     = {.str = "odp_event_free()_sp"},
	[_ODP_EV_EVENT_IS_VALID]    = {.str = "odp_event_is_valid()"},
	[_ODP_EV_PACKET_FREE]       = {.str = "odp_packet_free()"},
	[_ODP_EV_PACKET_FREE_MULTI] = {.str = "odp_packet_free_multi()"},
	[_ODP_EV_PACKET_FREE_SP]    = {.str = "odp_packet_free_sp()"},
	[_ODP_EV_PACKET_IS_VALID]   = {.str = "odp_packet_is_valid()"},
	[_ODP_EV_QUEUE_ENQ]         = {.str = "odp_queue_enq()"},
	[_ODP_EV_QUEUE_ENQ_MULTI]   = {.str = "odp_queue_enq_multi()"}
};

ODP_STATIC_ASSERT(_ODP_ARRAY_SIZE(ev_info_tbl) == _ODP_EV_MAX, "ev_info_tbl missing entries");

static void print_event_data(odp_event_t event, odp_event_type_t type)
{
	const char *type_str;
	const uint32_t bytes_per_row = 16;
	uint32_t byte_len;
	int num_rows, max_len, n;
	int len = 0;
	uint8_t *data;

	if (type == ODP_EVENT_PACKET) {
		odp_packet_t pkt = odp_packet_from_event(event);

		data = odp_packet_data(pkt);
		byte_len = odp_packet_seg_len(pkt);
		type_str = "Packet";
	} else {
		odp_buffer_t buf = odp_buffer_from_event(event);

		data = odp_buffer_addr(buf);
		byte_len = odp_buffer_size(buf);
		type_str = "Buffer";
	}

	if (byte_len > EVENT_DATA_PRINT_MAX_LEN)
		byte_len = EVENT_DATA_PRINT_MAX_LEN;

	num_rows = (byte_len + bytes_per_row - 1) / bytes_per_row;
	max_len = 256 + (3 * byte_len) + (3 * num_rows);
	n = max_len - 1;

	char str[max_len];

	len += _odp_snprint(&str[len], n - len, "%s %p data %p:\n", type_str, event, data);
	while (byte_len) {
		uint32_t row_len = byte_len > bytes_per_row ? bytes_per_row : byte_len;

		len += _odp_snprint(&str[len], n - len, " ");

		for (uint32_t i = 0; i < row_len; i++)
			len += _odp_snprint(&str[len], n - len, " %02x", data[i]);

		len += _odp_snprint(&str[len], n - len, "\n");

		byte_len -= row_len;
		data += row_len;
	}

	_ODP_PRINT("%s\n", str);
}

static inline int validate_event_endmark(odp_event_t event, _odp_ev_id_t id, odp_event_type_t type)
{
	uint64_t err_count;
	uint64_t *endmark_ptr = _odp_event_endmark_get_ptr(event);

	if (odp_likely(*endmark_ptr == _ODP_EV_ENDMARK_VAL))
		return 0;

	err_count = odp_atomic_fetch_inc_u64(&_odp_ev_glb->err_count[id]) + 1;

	_ODP_ERR("Event %p endmark mismatch in %s: endmark=0x%" PRIx64 " (expected 0x%" PRIx64 ") "
		 "err_count=%" PRIu64 "\n", event, ev_info_tbl[id].str, *endmark_ptr,
		 _ODP_EV_ENDMARK_VAL, err_count);

	print_event_data(event, type);

	if (_ODP_EVENT_VALIDATION == EVENT_VALIDATION_ABORT)
		_ODP_ABORT("Abort due to event %p endmark mismatch\n", event);

	/* Fix endmark value */
	_odp_event_endmark_set(event);

	return -1;
}

static inline int buffer_validate(odp_buffer_t buf, _odp_ev_id_t id)
{
	return validate_event_endmark(odp_buffer_to_event(buf), id, ODP_EVENT_BUFFER);
}

static inline int packet_validate(odp_packet_t pkt, _odp_ev_id_t id)
{
	return validate_event_endmark(odp_packet_to_event(pkt), id, ODP_EVENT_PACKET);
}

static inline int event_validate(odp_event_t event, int id)
{
	if (odp_event_type(event) == ODP_EVENT_BUFFER)
		return buffer_validate(odp_buffer_from_event(event), id);
	if (odp_event_type(event) == ODP_EVENT_PACKET)
		return packet_validate(odp_packet_from_event(event), id);
	return 0;
}

/* Enable usage from API inline files */
#include <odp/visibility_begin.h>

int _odp_buffer_validate(odp_buffer_t buf, _odp_ev_id_t id)
{
	return buffer_validate(buf, id);
}

int _odp_buffer_validate_multi(const odp_buffer_t buf[], int num,
			       _odp_ev_id_t id)
{
	for (int i = 0; i < num; i++) {
		if (odp_unlikely(buffer_validate(buf[i], id)))
			return -1;
	}
	return 0;
}

int _odp_packet_validate(odp_packet_t pkt, _odp_ev_id_t id)
{
	return packet_validate(pkt, id);
}

int _odp_packet_validate_multi(const odp_packet_t pkt[], int num,
			       _odp_ev_id_t id)
{
	for (int i = 0; i < num; i++) {
		if (odp_unlikely(packet_validate(pkt[i], id)))
			return -1;
	}
	return 0;
}

int _odp_event_validate(odp_event_t event, _odp_ev_id_t id)
{
	return event_validate(event, id);
}

int _odp_event_validate_multi(const odp_event_t event[], int num,
			      _odp_ev_id_t id)
{
	for (int i = 0; i < num; i++) {
		if (odp_unlikely(event_validate(event[i], id)))
			return -1;
	}
	return 0;
}

#include <odp/visibility_end.h>

#endif /* _ODP_EVENT_VALIDATION */

int _odp_event_validation_init_global(void)
{
	odp_shm_t shm;

	_ODP_PRINT("\nEvent validation mode: %s\n\n",
		   _ODP_EVENT_VALIDATION == EVENT_VALIDATION_NONE ? "none" :
		   _ODP_EVENT_VALIDATION == EVENT_VALIDATION_WARN ? "warn" : "abort");

	if (_ODP_EVENT_VALIDATION == EVENT_VALIDATION_NONE)
		return 0;

	shm = odp_shm_reserve("_odp_event_validation_global",
			      sizeof(event_validation_global_t),
			      ODP_CACHE_LINE_SIZE, ODP_SHM_EXPORT);
	if (shm == ODP_SHM_INVALID)
		return -1;

	_odp_ev_glb = odp_shm_addr(shm);
	if (_odp_ev_glb == NULL)
		return -1;

	memset(_odp_ev_glb, 0, sizeof(event_validation_global_t));
	_odp_ev_glb->shm = shm;

	for (int i = 0; i < _ODP_EV_MAX; i++)
		odp_atomic_init_u64(&_odp_ev_glb->err_count[i], 0);

	return 0;
}

int _odp_event_validation_term_global(void)
{
	int ret;

	if (_ODP_EVENT_VALIDATION == EVENT_VALIDATION_NONE)
		return 0;

	if (_odp_ev_glb == NULL)
		return 0;

	ret = odp_shm_free(_odp_ev_glb->shm);
	if (ret) {
		_ODP_ERR("SHM free failed: %d\n", ret);
		return -1;
	}

	return 0;
}
