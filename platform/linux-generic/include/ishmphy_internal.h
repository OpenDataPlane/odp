/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

#ifndef _ISHMPHY_INTERNAL_H_
#define _ISHMPHY_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

void *_ishmphy_book_va(uint64_t len);
int _ishmphy_unbook_va(void);
void *_ishmphy_map(int fd, void *start, uint64_t size,
		   int flags, int mmap_flags);
int _ishmphy_unmap(void *start, uint64_t len, int flags);

#ifdef __cplusplus
}
#endif

#endif
