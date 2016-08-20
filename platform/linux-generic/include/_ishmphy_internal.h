/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ISHMPHY_INTERNAL_H
#define _ISHMPHY_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

void *_odp_ishmphy_book_va(uintptr_t len, intptr_t align);
int   _odp_ishmphy_unbook_va(void);
void *_odp_ishmphy_map(int fd, void *start, uint64_t size, int flags);
int   _odp_ishmphy_unmap(void *start, uint64_t len, int flags);

#ifdef __cplusplus
}
#endif

#endif
