/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_L3FWD_LPM_H_
#define _ODP_L3FWD_LPM_H_

#ifdef __cplusplus
extern "C" {
#endif
void fib_tbl_init(void);
void fib_tbl_insert(uint32_t ip, int port, int depth);
int fib_tbl_lookup(uint32_t ip, int *port);
#ifdef __cplusplus
}
#endif

#endif
