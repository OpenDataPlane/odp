/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV memory barriers
 */

#ifndef ODPDRV_API_SYNC_H_
#define ODPDRV_API_SYNC_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odpdrv_barrier
 * @details
 * <b> Memory barriers </b>
 *
 * Memory barriers enforce ordering of memory load and store operations
 * specified before and after the barrier. These barriers may affect both
 * compiler optimizations and CPU out-of-order execution. All ODPDRV
 * synchronization mechanisms (e.g. execution barriers, locks, queues, etc )
 * include all necessary memory barriers, so these calls are not needed when
 * using those. Also ODPDRV atomic operations have memory ordered versions.
 * These explicit barriers may be needed when thread synchronization is based on
 * a non-ODPDRV defined mechanism. Depending on the HW platform, heavy usage of
 * memory barriers may cause significant performance degradation.
 *
 *  @{
 */

/**
 * Memory barrier for release operations
 *
 * This memory barrier has release semantics. It synchronizes with a pairing
 * barrier for acquire operations. The releasing and acquiring threads
 * synchronize through shared memory. The releasing thread must call this
 * barrier before signaling the acquiring thread. After the acquiring thread
 * receives the signal, it must call odpdrv_mb_acquire() before it reads the
 * memory written by the releasing thread.
 *
 * This call is not needed when using ODPDRV defined synchronization mechanisms.
 *
 * @see odpdrv_mb_acquire()
 */
void odpdrv_mb_release(void);

/**
 * Memory barrier for acquire operations
 *
 * This memory barrier has acquire semantics. It synchronizes with a pairing
 * barrier for release operations. The releasing and acquiring threads
 * synchronize through shared memory. The releasing thread must call
 * odpdrv_mb_release() before signaling the acquiring thread. After the
 * acquiring thread receives the signal, it must call this barrier before it
 * read the memory written by the releasing thread.
 *
 * This call is not needed when using ODPDRV defined synchronization mechanisms.
 *
 * @see odpdrv_mb_release()
 */
void odpdrv_mb_acquire(void);

/**
 * Full memory barrier
 *
 * This is a full memory barrier. It guarantees that all load and store
 * operations specified before it are visible to other threads before
 * all load and store operations specified after it.
 *
 * This call is not needed when using ODPDRV defined synchronization mechanisms.
 */
void odpdrv_mb_full(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
