/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 */

#ifndef ODP_PLAT_THREAD_INLINES_API_H_
#define ODP_PLAT_THREAD_INLINES_API_H_

#ifdef __cplusplus
extern "C" {
#endif

_ODP_INLINE int odp_thread_id(void)
{
	return _odp_thread_id();
}

_ODP_INLINE odp_thread_type_t odp_thread_type(void)
{
	return _odp_thread_type();
}

_ODP_INLINE int odp_cpu_id(void)
{
	return _odp_cpu_id();
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
