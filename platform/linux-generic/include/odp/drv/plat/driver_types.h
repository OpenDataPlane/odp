/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODPDRV_DRIVER_TYPES_H_
#define ODPDRV_DRIVER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/drv/std_types.h>
#include <odp/drv/plat/strong_types.h>

/** @addtogroup odpdrv_driver ODPDRV DRIVER
 *  Operations on driver related items (enumerator class, enumerators,
 *  devios and drivers).
 *  @{
 */

typedef ODPDRV_HANDLE_T(odpdrv_enumr_class_t);
#define ODPDRV_ENUMR_CLASS_INVALID _odpdrv_cast_scalar(odpdrv_enumr_class_t, 0)

typedef ODPDRV_HANDLE_T(odpdrv_enumr_t);
#define ODPDRV_ENUMR_INVALID _odpdrv_cast_scalar(odpdrv_enumr_t, 0)

typedef ODPDRV_HANDLE_T(odpdrv_device_t);
#define ODPDRV_DEVICE_INVALID _odpdrv_cast_scalar(odpdrv_device_t, 0)

typedef ODPDRV_HANDLE_T(odpdrv_devio_t);
#define ODPDRV_DEVIO_INVALID _odpdrv_cast_scalar(odpdrv_devio_t, 0)

typedef ODPDRV_HANDLE_T(odpdrv_driver_t);
#define ODPDRV_DRIVER_INVALID _odpdrv_cast_scalar(odpdrv_driver_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
