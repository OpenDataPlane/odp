/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Inline functions for ODP buffer mgmt routines - implementation internal
 */

#ifndef ODP_BUFFER_INLINES_H_
#define ODP_BUFFER_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_buffer_internal.h>

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf);
void _odp_buffer_event_type_set(odp_buffer_t buf, int ev);
odp_event_subtype_t _odp_buffer_event_subtype(odp_buffer_t buf);
void _odp_buffer_event_subtype_set(odp_buffer_t buf, int ev);
int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline odp_buffer_t buf_from_buf_hdr(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

#ifdef __cplusplus
}
#endif

#endif
