/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_ORDERED_INTERNAL_H_
#define ODP_SCHEDULE_ORDERED_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SUSTAIN_ORDER 1

int schedule_ordered_queue_enq(uint32_t queue_index, void *p_buf_hdr,
			       int sustain, int *ret);
int schedule_ordered_queue_enq_multi(uint32_t queue_index, void *p_buf_hdr[],
				     int num, int sustain, int *ret);

#ifdef __cplusplus
}
#endif

#endif
