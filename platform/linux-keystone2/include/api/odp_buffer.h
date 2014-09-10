/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer descriptor
 */

#ifndef ODP_BUFFER_H_
#define ODP_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_ti_mcsdk.h>

/**
 * ODP buffer
 */
typedef Ti_Pkt * odp_buffer_t;

#define ODP_BUFFER_INVALID ((odp_buffer_t)0) /**< Invalid buffer */

/**
 * @internal Convert ODP buffer to PKTLIB packet handle
 *
 * @param buf   Buffer handle
 *
 * @return PKTLIB packet handle
 */
static inline Ti_Pkt *_odp_buf_to_ti_pkt(odp_buffer_t buf)
{
	return (Ti_Pkt *)buf;
}

/**
 * @internal Convert PKTLIB packet handle to ODP buffer
 *
 * @param pkt   PKTLIB packet handle
 *
 * @return ODP buffer handle
 */
static inline odp_buffer_t _ti_pkt_to_odp_buf(Ti_Pkt *pkt)
{
	return (odp_buffer_t)pkt;
}

/**
 * @internal Convert ODP buffer to CPPI descriptor
 *
 * @param buf   Buffer handle
 *
 * @return CPPI descriptor
 */
static inline Cppi_HostDesc *_odp_buf_to_cppi_desc(odp_buffer_t buf)
{
	return Pktlib_getDescFromPacket(_odp_buf_to_ti_pkt(buf));
}

/**
 * @internal Convert CPPI descriptor to ODP buffer
 *
 * @param desc  CPPI descriptor pointer
 *
 * @return ODP buffer handle
 */
static inline odp_buffer_t _cppi_desc_to_odp_buf(Cppi_HostDesc *desc)
{
	return _ti_pkt_to_odp_buf(Pktlib_getPacketFromDesc(desc));
}

/**
 * Buffer start address
 *
 * @param buf      Buffer handle
 *
 * @return Buffer start address
 */
static inline void *odp_buffer_addr(odp_buffer_t buf)
{
	return (void *)_odp_buf_to_cppi_desc(buf)->buffPtr;
}

/**
 * Buffer maximum data size
 *
 * @param buf      Buffer handle
 *
 * @return Buffer maximum data size
 */
static inline size_t odp_buffer_size(odp_buffer_t buf)
{
	return _odp_buf_to_cppi_desc(buf)->buffLen;
}

#define ODP_BUFFER_TYPE_INVALID (-1) /**< Buffer type invalid */
#define ODP_BUFFER_TYPE_ANY       0  /**< Buffer that can hold any other
					  buffer type */
#define ODP_BUFFER_TYPE_RAW       1  /**< Raw buffer, no additional metadata */
#define ODP_BUFFER_TYPE_PACKET    2  /**< Packet buffer */
#define ODP_BUFFER_TYPE_TIMEOUT   3  /**< Timeout buffer */
/**
 * Buffer type
 *
 * @param buf      Buffer handle
 *
 * @return Buffer type
 */
static inline int odp_buffer_type(odp_buffer_t buf)
{
	return Pktlib_getUsrFlags(_odp_buf_to_ti_pkt(buf));
}

/**
 * Tests if buffer is valid
 *
 * @param buf      Buffer handle
 *
 * @return 1 if valid, otherwise 0
 */
static inline int odp_buffer_is_valid(odp_buffer_t buf)
{
	return (buf != ODP_BUFFER_INVALID);
}

/**
 * Print buffer metadata to STDOUT
 *
 * @param buf      Buffer handle
 */
void odp_buffer_print(odp_buffer_t buf);

/**
 * @internal Set buffer user context
 *
 * @param buffer   Buffer handle
 * @param context  User context
 */
static inline void odp_buffer_set_ctx(odp_buffer_t buffer, void *context)
{
	Cppi_setTimeStamp(Cppi_DescType_HOST,
			  (Cppi_Desc *)_odp_buf_to_cppi_desc(buffer),
			  (uint32_t) context);
}

/**
 * @internal Get buffer user context
 *
 * @param buffer   Buffer handle
 *
 * @return User context
 */
static inline void *odp_buffer_get_ctx(odp_buffer_t buffer)
{
	uint32_t app_ctx_id = 0;
	Cppi_getTimeStamp(Cppi_DescType_HOST,
			  (Cppi_Desc *)_odp_buf_to_cppi_desc(buffer),
			  &app_ctx_id);
	return (void *)app_ctx_id;
}

#ifdef __cplusplus
}
#endif

#endif
