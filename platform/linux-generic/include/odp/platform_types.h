/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 * ODP implementation types
 * This file contains all of the implementation-defined types for ODP abstract
 * definitions. Having this in one file means that other ODP API files are
 * implementation-independent and avoids circular dependencies for files that
 * refer to types managed by other components. Included here are typedefs and
 * related typed constants that are referenced by other ODP API files.
 */

#ifndef ODP_IMPL_TYPES_H_
#define ODP_IMPL_TYPES_H_

/** @defgroup odp_platform_types ODP PLATFORM TYPES
 *  Implementation specific definitions for ODP abstract types.
 *  @{
 */

/** ODP buffer */
typedef uint32_t odp_buffer_t;

/** Invalid buffer */
#define ODP_BUFFER_INVALID (0xffffffff)

/** ODP buffer segment */
typedef odp_buffer_t odp_buffer_seg_t;

/** Invalid segment */
#define ODP_SEGMENT_INVALID ODP_BUFFER_INVALID

/** ODP packet */
typedef odp_buffer_t odp_packet_t;

/** Invalid packet */
#define ODP_PACKET_INVALID ODP_BUFFER_INVALID

/** Invalid packet offset */
#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

/** ODP packet segment */
typedef odp_buffer_t odp_packet_seg_t;

/** Invalid packet segment */
#define ODP_PACKET_SEG_INVALID ODP_BUFFER_INVALID

/** ODP packet IO handle */
typedef uint32_t odp_pktio_t;

/** Invalid packet IO handle */
#define ODP_PKTIO_INVALID 0

/** odp_pktio_t value to indicate any port */
#define ODP_PKTIO_ANY ((odp_pktio_t)~0)

/** ODP event */
typedef odp_buffer_t odp_event_t;

/** Invalid event */
#define ODP_EVENT_INVALID ODP_BUFFER_INVALID

/**
 * ODP shared memory block
 */
typedef uint32_t odp_shm_t;

/** Invalid shared memory block */
#define ODP_SHM_INVALID 0
#define ODP_SHM_NULL ODP_SHM_INVALID /**< Synonym for buffer pool use */

/** ODP Class of service handle */
typedef uint32_t odp_cos_t;

/**
 * @}
 */

#endif
