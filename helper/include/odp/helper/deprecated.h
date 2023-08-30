/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * Macro for deprecated API definitions
 */

#ifndef ODPH_DEPRECATED_H_
#define ODPH_DEPRECATED_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/helper/autoheader_external.h>

/**
 * @def ODPH_DEPRECATE
 *
 * Macro to deprecate helper API definitions
 */

#if ODPH_DEPRECATED_API
#define ODPH_DEPRECATE(x) x
#else
#define ODPH_DEPRECATE(x) _deprecated_ ## x
#endif

#ifdef __cplusplus
}
#endif

#endif
