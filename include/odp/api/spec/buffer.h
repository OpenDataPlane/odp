/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2022-2023 Nokia
 */

/**
 * @file
 *
 * ODP buffer
 */

#ifndef ODP_API_SPEC_BUFFER_H_
#define ODP_API_SPEC_BUFFER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/buffer_types.h>
#include <odp/api/event_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>

/** @defgroup odp_buffer ODP BUFFER
 *  Buffer event metadata and operations.
 *  @{
 */

/**
 * Get buffer handle from event
 *
 * Converts an ODP_EVENT_BUFFER type event to a buffer.
 *
 * @param ev   Event handle
 *
 * @return Buffer handle
 *
 * @see odp_event_type()
 */
odp_buffer_t odp_buffer_from_event(odp_event_t ev);

/**
 * Convert multiple buffer events to buffer handles
 *
 * All events must be of type ODP_EVENT_BUFFER.
 *
 * @param[out] buf  Buffer handle array for output
 * @param      ev   Array of event handles to convert
 * @param      num  Number of buffers and events
 */
void odp_buffer_from_event_multi(odp_buffer_t buf[], const odp_event_t ev[], int num);

/**
 * Convert buffer handle to event
 *
 * @param buf  Buffer handle
 *
 * @return Event handle
 */
odp_event_t odp_buffer_to_event(odp_buffer_t buf);

/**
 * Convert multiple buffer handles to events
 *
 * @param      buf  Array of buffer handles to convert
 * @param[out] ev   Event handle array for output
 * @param      num  Number of buffers and events
 */
void odp_buffer_to_event_multi(const odp_buffer_t buf[], odp_event_t ev[], int num);

/**
 * Buffer start address
 *
 * @param buf      Buffer handle
 *
 * @return Buffer start address
 */
void *odp_buffer_addr(odp_buffer_t buf);

/**
 * Buffer maximum data size
 *
 * @param buf      Buffer handle
 *
 * @return Buffer maximum data size
 */
uint32_t odp_buffer_size(odp_buffer_t buf);

/**
 * Buffer user area
 *
 * Returns pointer to the user area associated with the buffer. Size of the area is fixed
 * and defined in buffer pool parameters.
 *
 * @param buf      Buffer handle
 *
 * @return       Pointer to the user area of the buffer
 * @retval NULL  The buffer does not have user area
 */
void *odp_buffer_user_area(odp_buffer_t buf);

/**
 * Check that buffer is valid
 *
 * This function can be used for debugging purposes to check if a buffer handle represents
 * a valid buffer. The level of error checks depends on the implementation. The call should not
 * crash if the buffer handle is corrupted.
 *
 * @param buf      Buffer handle
 *
 * @retval 1 Buffer handle represents a valid buffer.
 * @retval 0 Buffer handle does not represent a valid buffer.
 */
int odp_buffer_is_valid(odp_buffer_t buf);

/**
 * Buffer pool of the buffer
 *
 * @param buf       Buffer handle
 *
 * @return Handle of buffer pool buffer belongs to
 */
odp_pool_t odp_buffer_pool(odp_buffer_t buf);

/**
 * Buffer alloc
 *
 * Allocates a buffer from the pool. Returns ODP_BUFFER_INVALID when a buffer
 * can not be allocated.
 *
 * @param pool      Pool handle
 *
 * @return Handle of allocated buffer
 * @retval ODP_BUFFER_INVALID  Buffer could not be allocated
 */
odp_buffer_t odp_buffer_alloc(odp_pool_t pool);

/**
 * Allocate multiple buffers
 *
 * Otherwise like odp_buffer_alloc(), but allocates multiple buffers from a pool.
 *
 * @param pool      Pool handle
 * @param[out] buf  Array of buffer handles for output
 * @param num       Maximum number of buffers to allocate
 *
 * @return Number of buffers actually allocated (0 ... num)
 * @retval <0 on failure
 */
int odp_buffer_alloc_multi(odp_pool_t pool, odp_buffer_t buf[], int num);

/**
 * Buffer free
 *
 * @param buf       Buffer handle
 *
 */
void odp_buffer_free(odp_buffer_t buf);

/**
 * Free multiple buffers
 *
 * Otherwise like odp_buffer_free(), but frees multiple buffers
 * to their originating pools.
 *
 * @param buf        Array of buffer handles
 * @param num        Number of buffer handles to free
 *
 */
void odp_buffer_free_multi(const odp_buffer_t buf[], int num);

/**
 * Print buffer metadata to STDOUT
 *
 * @param buf      Buffer handle
 *
 */
void odp_buffer_print(odp_buffer_t buf);

/**
 * Get printable value for an odp_buffer_t
 *
 * @param hdl  odp_buffer_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_buffer_t handle.
 */
uint64_t odp_buffer_to_u64(odp_buffer_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
