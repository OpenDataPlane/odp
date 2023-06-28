/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 */

/**
 * @file
 *
 * ODP memory barriers
 */

#ifndef ODP_API_SPEC_SYNC_H_
#define ODP_API_SPEC_SYNC_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup odp_barrier
 * @details
 * <b> Memory barriers </b>
 *
 * A memory barrier enforces the order between memory accesses (loads and/or stores)
 * specified (in program order) before the barrier with those specified after the barrier.
 * A barrier may affect both compiler optimizations and CPU out-of-order execution. Depending
 * on the used HW platform and barrier types, heavy usage of barriers may cause significant
 * performance degradation.
 *
 * An application may use these memory barrier functions e.g. to build a synchronization
 * mechanism between its threads in shared memory, or when it accesses memory mapped registers
 * of a device.
 *
 * An application does not need to use these memory barriers when using other ODP APIs for thread
 * synchronization (execution barriers, spinlocks, etc.), or when exchanging data through ODP API
 * mechanisms (queues, stashes, etc.). Those ODP calls include necessary (acquire and release)
 * memory barriers to maintain coherency between data producers and consumers.
 *
 * Some ODP atomic operations include a memory barrier - see for example odp_atomic_load_acq_u32()
 * or odp_atomic_store_rel_u32(). Application may use also those (non-relaxed) atomic operations
 * to enforce memory ordering while using atomic variables.
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
 * receives the signal, it must call odp_mb_acquire() before it reads the
 * memory written by the releasing thread.
 *
 * This call is not needed when using ODP defined synchronization mechanisms.
 *
 * @see odp_mb_acquire()
 */
void odp_mb_release(void);

/**
 * Memory barrier for acquire operations
 *
 * This memory barrier has acquire semantics. It synchronizes with a pairing
 * barrier for release operations. The releasing and acquiring threads
 * synchronize through shared memory. The releasing thread must call
 * odp_mb_release() before signaling the acquiring thread. After the acquiring
 * thread receives the signal, it must call this barrier before it reads the
 * memory written by the releasing thread.
 *
 * This call is not needed when using ODP defined synchronization mechanisms.
 *
 * @see odp_mb_release()
 */
void odp_mb_acquire(void);

/**
 * Full memory barrier
 *
 * This is a full memory barrier. It guarantees that all load and store
 * operations specified before it are visible to other threads before
 * all load and store operations specified after it.
 *
 * This call is not needed when using ODP defined synchronization mechanisms.
 */
void odp_mb_full(void);

/**
 * Memory barrier for load and store synchronization
 *
 * This memory barrier ensures that all memory accesses (loads and stores) specified before the
 * barrier (in program order) are complete prior to any memory access specified after the barrier
 * begins execution.
 *
 * This is a stronger barrier than odp_mb_full(), as in addition to visibility order also memory
 * access completion is ensured. The barrier may be useful e.g. when synchronizing loads and stores
 * into memory mapped registers of a device.
 */
void odp_mb_sync(void);

/**
 * Memory barrier for load synchronization
 *
 * This memory barrier ensures that all memory loads specified before the barrier (in program
 * order) are complete prior to any memory load specified after the barrier begins execution.
 *
 * The barrier may be useful e.g. when synchronizing loads from memory mapped registers of a device.
 */
void odp_mb_sync_load(void);

/**
 * Memory synchronization barrier for stores
 *
 * This memory barrier ensures that all memory stores specified before the barrier (in program
 * order) are complete prior to any memory store specified after the barrier begins execution.
 *
 * The barrier may be useful e.g. when synchronizing stores to memory mapped registers of a device.
 */
void odp_mb_sync_store(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
