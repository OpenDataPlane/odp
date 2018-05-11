/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __INSTRUM_PAPI_COUNTERS_H__
#define __INSTRUM_PAPI_COUNTERS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sample.h>

int papi_init(void);
void papi_term(void);
int papi_init_local(void);
int papi_term_local(void);

int papi_counters_cnt(void);

int papi_sample_start(profiling_sample_t *spl);
int papi_sample_end(profiling_sample_t *spl);

#ifdef __cplusplus
}
#endif
#endif /* __INSTRUM_PAPI_COUNTERS_H__ */
