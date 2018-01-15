/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __INSTRUM_SAMPLE_H__
#define __INSTRUM_SAMPLE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SAMPLE_NAME_SIZE_MAX 20
#define SAMPLE_COUNTER_TAB_SIZE 10

typedef struct {
	char name[SAMPLE_NAME_SIZE_MAX];
	long long timestamp_ns;
	long long diff_cyc;

	long long counters[SAMPLE_COUNTER_TAB_SIZE];
} profiling_sample_t;

#ifdef __cplusplus
}
#endif
#endif /* __INSTRUM_SAMPLE_H__ */

