/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP internal IPsec routines
 */

#ifndef ODP_IPSEC_INTERNAL_H_
#define ODP_IPSEC_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp/api/byteorder.h>
#include <odp/api/ipsec.h>
#include <odp/api/ticketlock.h>

/** @ingroup odp_ipsec
 *  @{
 */

typedef ODP_HANDLE_T(ipsec_result_t);

#define ODP_IPSEC_RESULT_INVALID \
	_odp_cast_scalar(ipsec_result_t, 0xffffffff)

typedef ODP_HANDLE_T(ipsec_status_t);

#define ODP_IPSEC_STATUS_INVALID \
	_odp_cast_scalar(ipsec_status_t, 0xffffffff)

typedef struct ipsec_ctx_s ipsec_ctx_t;

typedef struct ipsec_sa_s ipsec_sa_t;

/**
 * @internal Free IPsec context
 *
 * Frees the IPsec context into the pool it was allocated from.
 *
 * @param ctx		IPsec context
 */
void _odp_ipsec_ctx_free(ipsec_ctx_t *ctx);

/**
 * @internal Process context filling operation result information
 *
 * Processes IPsec operation context related to completed operation, extracting
 * operation result information. This function may update context provided via
 * pointer to opaque context pointer.
 *
 * @param         ctx     IPsec context pointer.
 * @param[out]    result  Pointer to operation result for output. May be
 *                        NULL, if application is interested only on the
 *                        number of packets.
 *
 * @return Number of packets remaining in the event.
 * @retval <0     On failure
 */
int _odp_ipsec_ctx_result(ipsec_ctx_t *ctx, odp_ipsec_op_result_t *result);

/**
 * @internal Get ipsec_result handle from event
 *
 * Converts an ODP_EVENT_IPSEC_RESULT type event to an IPsec result event.
 *
 * @param ev   Event handle
 *
 * @return IPsec result handle
 *
 * @see odp_event_type()
 */
ipsec_result_t _odp_ipsec_result_from_event(odp_event_t ev);

/**
 * @internal Free IPsec result event
 *
 * Frees the ipsec_result into the ipsec_result pool it was allocated from.
 *
 * @param res           IPsec result handle
 */
void _odp_ipsec_result_free(ipsec_result_t res);

/**
 * @internal Send ODP_IPSEC_RESULT event
 *
 * Sends the ipsec_result event using provided information
 *
 * @param queue         destination queue
 * @param ctx           IPsec context for the operation
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_ipsec_result_send(odp_queue_t queue, ipsec_ctx_t *ctx);

/**
 * @internal Get ipsec_status handle from event
 *
 * Converts an ODP_EVENT_IPSEC_STATUS type event to an IPsec status event.
 *
 * @param ev   Event handle
 *
 * @return IPsec status handle
 *
 * @see odp_event_type()
 */
ipsec_status_t _odp_ipsec_status_from_event(odp_event_t ev);

/**
 * @internal Free IPsec status event
 *
 * Frees the ipsec_status into the ipsec_status pool it was allocated from.
 *
 * @param res           IPsec status handle
 */
void _odp_ipsec_status_free(ipsec_status_t status);

/**
 * @internal Send ODP_IPSEC_STATUS event
 *
 * Sends the ipsec_status event using provided information
 *
 * @param queue         destination queue
 * @param id            status id
 * @param ret           status value
 * @param sa            SA respective to the operation
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_ipsec_status_send(odp_queue_t queue,
			   odp_ipsec_status_id_t id,
			   int ret,
			   odp_ipsec_sa_t sa);

#define IPSEC_MAX_IV_LEN	32   /**< Maximum IV length in bytes */

/**
 * Maximum number of available SAs
 */
#define ODP_CONFIG_IPSEC_SAS	8

struct ipsec_sa_s {
	odp_atomic_u32_t state ODP_ALIGNED_CACHE;

	unsigned	in_place : 1;
	unsigned	dec_ttl : 1;
	unsigned	copy_dscp : 1;
	unsigned	copy_df : 1;

	uint8_t		tun_ttl;

	odp_ipsec_sa_t	ipsec_sa_hdl;
	uint32_t	ipsec_sa_idx;

	odp_ipsec_mode_t mode;
	odp_ipsec_lookup_mode_t lookup_mode;
	odp_crypto_session_t session;
	void		*context;
	odp_queue_t	queue;

	odp_u32be_t	lookup_dst_ip;
	odp_u32be_t	tun_src_ip;
	odp_u32be_t	tun_dst_ip;

	odp_ipsec_protocol_t proto;
	uint32_t	icv_len;
	uint32_t	esp_iv_len;
	uint32_t	esp_block_len;
	uint32_t	spi;

	/* 32-bit from which low 16 are used */
	odp_atomic_u32_t tun_hdr_id;
	odp_atomic_u32_t seq;

	/* Limits */
	uint64_t soft_limit_bytes;
	uint64_t soft_limit_packets;
	uint64_t hard_limit_bytes;
	uint64_t hard_limit_packets;

	/* Statistics for soft/hard expiration */
	odp_atomic_u64_t bytes;
	odp_atomic_u64_t packets;

	uint8_t tun_dscp;
	uint8_t tun_df;
};

/**
 * IPSEC Security Association (SA) lookup parameters
 */
typedef struct odp_ipsec_sa_lookup_s {
	/** IPSEC protocol: ESP or AH */
	odp_ipsec_protocol_t proto;

	/** SPI value */
	uint32_t spi;

	/* FIXME: IPv4 vs IPv6 */

	/** IP destination address (NETWORK ENDIAN) */
	void    *dst_addr;
} ipsec_sa_lookup_t;

/**
 * Obtain SA reference
 */
ipsec_sa_t *_odp_ipsec_sa_use(odp_ipsec_sa_t sa);

/**
 * Release SA reference
 */
void _odp_ipsec_sa_unuse(ipsec_sa_t *ipsec_sa);

/**
 * Lookup SA corresponding to inbound packet pkt
 */
ipsec_sa_t *_odp_ipsec_sa_lookup(const ipsec_sa_lookup_t *lookup);

/**
 * Update SA usage statistics, filling respective status for the packet.
 *
 * @retval <0 if hard limits were breached
 */
int _odp_ipsec_sa_update_stats(ipsec_sa_t *ipsec_sa, uint32_t len,
			       odp_ipsec_op_status_t *status);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
