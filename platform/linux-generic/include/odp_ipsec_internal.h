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

#include <protocols/ip.h>

/** @ingroup odp_ipsec
 *  @{
 */

typedef ODP_HANDLE_T(ipsec_status_t);

#define ODP_IPSEC_STATUS_INVALID \
	_odp_cast_scalar(ipsec_status_t, 0xffffffff)

typedef struct ipsec_sa_s ipsec_sa_t;

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
 * @param sa            SA respective to the operation
 * @param result        status value
 * @param warn          generated warning
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int _odp_ipsec_status_send(odp_queue_t queue,
			   odp_ipsec_status_id_t id,
			   odp_ipsec_sa_t sa,
			   int result,
			   odp_ipsec_warn_t warn);

#define IPSEC_MAX_IV_LEN	32   /**< Maximum IV length in bytes */

#define IPSEC_MAX_SALT_LEN	4    /**< Maximum salt length in bytes */

/* 32 is minimum required by the standard. We do not support more */
#define IPSEC_ANTIREPLAY_WS	32

/**
 * Maximum number of available SAs
 */
#define ODP_CONFIG_IPSEC_SAS	8

struct ipsec_sa_s {
	odp_atomic_u32_t ODP_ALIGNED_CACHE state;

	uint32_t	ipsec_sa_idx;
	odp_ipsec_sa_t	ipsec_sa_hdl;

	odp_ipsec_protocol_t proto;
	uint32_t	spi;

	odp_ipsec_mode_t mode;

	/* Limits */
	uint64_t soft_limit_bytes;
	uint64_t soft_limit_packets;
	uint64_t hard_limit_bytes;
	uint64_t hard_limit_packets;

	/* Statistics for soft/hard expiration */
	odp_atomic_u64_t bytes;
	odp_atomic_u64_t packets;

	odp_crypto_session_t session;
	void		*context;
	odp_queue_t	queue;

	uint32_t	icv_len;
	uint32_t	esp_iv_len;
	uint32_t	esp_block_len;

	uint8_t		salt[IPSEC_MAX_SALT_LEN];
	uint32_t	salt_length;
	odp_ipsec_lookup_mode_t lookup_mode;

	union {
		unsigned flags;
		struct {
			unsigned	dec_ttl : 1;
			unsigned	copy_dscp : 1;
			unsigned	copy_df : 1;
			unsigned	copy_flabel : 1;
			unsigned	aes_ctr_iv : 1;
			unsigned	udp_encap : 1;

			/* Only for outbound */
			unsigned	use_counter_iv : 1;
			unsigned	tun_ipv4 : 1;

			/* Only for inbound */
			unsigned	antireplay : 1;
		};
	};

	union {
		struct {
			odp_ipsec_ip_version_t lookup_ver;
			union {
				odp_u32be_t	lookup_dst_ipv4;
				uint8_t lookup_dst_ipv6[_ODP_IPV6ADDR_LEN];
			};
			odp_atomic_u64_t antireplay;
		} in;

		struct {
			odp_atomic_u64_t counter; /* for CTR/GCM */
			odp_atomic_u32_t seq;
			odp_ipsec_frag_mode_t frag_mode;
			uint32_t mtu;

			union {
			struct {
				odp_u32be_t	src_ip;
				odp_u32be_t	dst_ip;

				/* 32-bit from which low 16 are used */
				odp_atomic_u32_t hdr_id;

				uint8_t		ttl;
				uint8_t		dscp;
				uint8_t		df;
			} tun_ipv4;
			struct {
				uint8_t		src_ip[_ODP_IPV6ADDR_LEN];
				uint8_t		dst_ip[_ODP_IPV6ADDR_LEN];
				uint8_t		hlimit;
				uint8_t		dscp;
				uint32_t	flabel;
			} tun_ipv6;
			};
		} out;
	};
};

/**
 * IPSEC Security Association (SA) lookup parameters
 */
typedef struct odp_ipsec_sa_lookup_s {
	/** IPSEC protocol: ESP or AH */
	odp_ipsec_protocol_t proto;

	/** SPI value */
	uint32_t spi;

	/** IP protocol version */
	odp_ipsec_ip_version_t ver;

	/** IP destination address (NETWORK ENDIAN) */
	void    *dst_addr;
} ipsec_sa_lookup_t;

/** IPSEC AAD */
typedef struct ODP_PACKED {
	odp_u32be_t spi;     /**< Security Parameter Index */
	odp_u32be_t seq_no;  /**< Sequence Number */
} ipsec_aad_t;

/* Return IV length required for the cipher for IPsec use */
uint32_t _odp_ipsec_cipher_iv_len(odp_cipher_alg_t cipher);

/* Return digest length required for the cipher for IPsec use */
uint32_t _odp_ipsec_auth_digest_len(odp_auth_alg_t auth);

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
 * Run pre-check on SA usage statistics.
 *
 * @retval <0 if hard limits were breached
 */
int _odp_ipsec_sa_stats_precheck(ipsec_sa_t *ipsec_sa,
				 odp_ipsec_op_status_t *status);

/**
 * Update SA usage statistics, filling respective status for the packet.
 *
 * @retval <0 if hard limits were breached
 */
int _odp_ipsec_sa_stats_update(ipsec_sa_t *ipsec_sa, uint32_t len,
			       odp_ipsec_op_status_t *status);

/* Run pre-check on sequence number of the packet.
 *
 * @retval <0 if the packet falls out of window
 */
int _odp_ipsec_sa_replay_precheck(ipsec_sa_t *ipsec_sa, uint32_t seq,
				  odp_ipsec_op_status_t *status);

/* Run check on sequence number of the packet and update window if necessary.
 *
 * @retval <0 if the packet falls out of window
 */
int _odp_ipsec_sa_replay_update(ipsec_sa_t *ipsec_sa, uint32_t seq,
				odp_ipsec_op_status_t *status);
/**
 * Try inline IPsec processing of provided packet.
 *
 * @retval 0 if packet was processed and will be queue using IPsec inline
 *           processing
 */
int _odp_ipsec_try_inline(odp_packet_t *pkt);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
