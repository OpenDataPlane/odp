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

/** ODP Buffer pool */
typedef uint32_t odp_buffer_pool_t;

/** Invalid buffer pool */
#define ODP_BUFFER_POOL_INVALID (0)

/** ODP buffer */
typedef uint32_t odp_buffer_t;

/** Invalid buffer */
#define ODP_BUFFER_INVALID (0xffffffff)

/** ODP packet */
typedef odp_buffer_t odp_packet_t;

/** Invalid packet */
#define ODP_PACKET_INVALID ODP_BUFFER_INVALID

/** Invalid offset */
#define ODP_PACKET_OFFSET_INVALID ((uint32_t)-1)

/** ODP packet segment */
typedef int odp_packet_seg_t;

/** Invalid packet segment */
#define ODP_PACKET_SEG_INVALID -1

/** ODP packet segment info */
typedef struct odp_packet_seg_info_t {
	void   *addr;      /**< Segment start address */
	size_t  size;      /**< Segment maximum data size */
	void   *data;      /**< Segment data address */
	size_t  data_len;  /**< Segment data length */
} odp_packet_seg_info_t;

/** ODP packet IO handle */
typedef uint32_t odp_pktio_t;

/** Invalid packet IO handle */
#define ODP_PKTIO_INVALID 0

/** odp_pktio_t value to indicate any port */
#define ODP_PKTIO_ANY ((odp_pktio_t)~0)

/**
 * ODP shared memory block
 */
typedef uint32_t odp_shm_t;

/** Invalid shared memory block */
#define ODP_SHM_INVALID 0

/**
 * @}
 */

#endif
