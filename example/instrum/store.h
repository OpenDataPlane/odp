/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __INSTRUM_STORE_H__
#define __INSTRUM_STORE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef void *instr_profiling_sample_t;

#define STORE_SAMPLE_INIT \
	instr_profiling_sample_t _spl

#define STORE_SAMPLE_START \
	(_spl = store_sample_start(__func__))

#define STORE_SAMPLE_END \
	store_sample_end(_spl)

int instr_store_init(void);
void instr_store_term(void);
int instr_store_init_local(void);
int instr_store_term_local(void);

instr_profiling_sample_t store_sample_start(const char *function_name);
void store_sample_end(instr_profiling_sample_t spl);

#ifdef __cplusplus
}
#endif
#endif /* __INSTRUM_STORE_H__ */
