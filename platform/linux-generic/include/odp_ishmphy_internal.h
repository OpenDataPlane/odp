/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

#ifndef _ISHMPHY_INTERNAL_H
#define _ISHMPHY_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void *_odp_ishmphy_reserve_single_va(uint64_t len, int fd);
int   _odp_ishmphy_free_single_va(void);
void *_odp_ishmphy_map(int fd, uint64_t size, uint64_t offset, int flags);
int   _odp_ishmphy_unmap(void *start, uint64_t len, int flags);

#ifdef __cplusplus
}
#endif

#endif
