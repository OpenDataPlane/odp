/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2018, 2020-2022, Nokia
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

#include <odp/api/atomic.h>
#include <odp/api/byteorder.h>
#include <odp/api/event.h>
#include <odp/api/ipsec.h>
#include <odp/api/spinlock.h>
#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#include <protocols/ip.h>
#include <stdint.h>

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

#define IPSEC_MAX_IV_LEN	16   /**< Maximum cipher IV length in bytes */

#define IPSEC_MAX_SALT_LEN	4    /**< Maximum salt length in bytes */

#define CBC_SALT_LEN		8
#define CBC_IV_LEN		(CBC_SALT_LEN + sizeof(uint64_t))

#define IPSEC_SEQ_HI_LEN	4    /**< ESN Higher bits length in bytes */

/* The minimum supported AR window size */
#define IPSEC_AR_WIN_SIZE_MIN	32

/* The maximum supported AR window size */
#define IPSEC_AR_WIN_SIZE_MAX	4096

/* For a 64-bit bucket size */
#define IPSEC_AR_WIN_BUCKET_BITS	6
#define IPSEC_AR_WIN_BUCKET_SIZE	(1 << IPSEC_AR_WIN_BUCKET_BITS)
#define IPSEC_AR_WIN_BITLOC_MASK	(IPSEC_AR_WIN_BUCKET_SIZE - 1)

/*
 * We need one extra bucket in addition to the buckets that contain
 * part of the window.
 */
#define IPSEC_AR_WIN_NUM_BUCKETS(window_size)	\
	(((window_size) - 1) / IPSEC_AR_WIN_BUCKET_SIZE + 2)

/* Maximum number of buckets */
#define IPSEC_AR_WIN_BUCKET_MAX		\
	IPSEC_AR_WIN_NUM_BUCKETS(IPSEC_AR_WIN_SIZE_MAX)

struct ipsec_sa_s {
	odp_atomic_u32_t state ODP_ALIGNED_CACHE;

	/*
	 * State that gets updated very frequently. Grouped separately
	 * to avoid false cache line sharing with other data.
	 */
	struct ODP_ALIGNED_CACHE {
		/* Statistics for soft/hard expiration */
		odp_atomic_u64_t bytes;
		odp_atomic_u64_t packets;

		union {
			struct {
				/* AR window lock */
				odp_spinlock_t lock;

				/* AR window top sequence number */
				odp_atomic_u64_t wintop_seq;

				/* AR window bucket array */
				uint64_t bucket_arr[IPSEC_AR_WIN_BUCKET_MAX];
			} in;

			struct {
				/*
				 * 64-bit sequence number that is also used as
				 * CTR/GCM IV
				 */
				odp_atomic_u64_t seq;
			} out;
		};
	} hot;

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

	odp_crypto_session_t session;
	void		*context;
	odp_queue_t	queue;

	uint32_t	icv_len;
	uint32_t	esp_iv_len;
	uint32_t	esp_pad_mask;

	union {
		uint8_t		salt[IPSEC_MAX_SALT_LEN];
		uint8_t         cbc_salt[CBC_SALT_LEN];
	};
	uint32_t	salt_length;
	odp_ipsec_lookup_mode_t lookup_mode;

	union {
		unsigned flags;
		struct {
			unsigned	inbound : 1;
			unsigned	dec_ttl : 1;
			unsigned	copy_dscp : 1;
			unsigned	copy_df : 1;
			unsigned	copy_flabel : 1;
			unsigned	aes_ctr_iv : 1;
			unsigned	udp_encap : 1;
			unsigned	esn : 1;
			unsigned	insert_seq_hi : 1;

			/* Only for outbound */
			unsigned	use_counter_iv : 1;
			unsigned	use_cbc_iv : 1;
			unsigned	tun_ipv4 : 1;

			/* Only for inbound */
			unsigned	antireplay : 1;
		};
	};

	union {
		struct {
			odp_ipsec_ip_version_t lookup_ver;

			/* Anti-replay window management. */
			struct {
				/* Number of buckets for AR window */
				uint16_t num_buckets;

				/* AR window size  */
				uint32_t win_size;
			} ar;

			union {
				odp_u32be_t	lookup_dst_ipv4;
				uint8_t lookup_dst_ipv6[_ODP_IPV6ADDR_LEN];
			};
		} in;

		struct {
			odp_ipsec_frag_mode_t frag_mode;
			odp_atomic_u32_t mtu;

			union {
			struct {
				odp_ipsec_ipv4_param_t param;
				odp_u32be_t	src_ip;
				odp_u32be_t	dst_ip;
			} tun_ipv4;
			struct {
				odp_ipsec_ipv6_param_t param;
				uint8_t		src_ip[_ODP_IPV6ADDR_LEN];
				uint8_t		dst_ip[_ODP_IPV6ADDR_LEN];
			} tun_ipv6;
			};
		} out;
	};

	struct {
		odp_atomic_u64_t proto_err;
		odp_atomic_u64_t auth_err;
		odp_atomic_u64_t antireplay_err;
		odp_atomic_u64_t alg_err;
		odp_atomic_u64_t mtu_err;
		odp_atomic_u64_t hard_exp_bytes_err;
		odp_atomic_u64_t hard_exp_pkts_err;

		/*
		 * Track error packets and bytes after lifetime check is done.
		 * Required since, the stats tracking lifetime is being
		 * used for SA success packets stats.
		 */
		odp_atomic_u64_t post_lifetime_err_pkts;
		odp_atomic_u64_t post_lifetime_err_bytes;
	} stats;

	uint32_t next_sa;

	/* Data stored solely for odp_ipsec_sa_info() */
	struct {
		odp_cipher_alg_t cipher_alg;
		uint32_t cipher_key_len;
		uint32_t cipher_key_extra_len;

		odp_auth_alg_t auth_alg;
		uint32_t auth_key_len;
		uint32_t auth_key_extra_len;

		uint32_t icv_len;
		uint32_t context_len;
		union {
			struct {
				uint32_t antireplay_ws;
			} in;
			struct{
				uint32_t mtu;
			} out;
		};
	} sa_info;

	/*
	 * Flag to check if the SA soft expiry status event was already
	 * sent. This field is applicable only for the soft expiry status
	 * event that gets generated for IPsec SAs configured in inline
	 * outbound mode.
	 */
	odp_atomic_u32_t soft_expiry_notified;
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
	/**< Security Parameter Index */
	odp_u32be_t spi;

	/**< Sequence Number */
	union {
		odp_u32be_t seq_no;
		odp_u64be_t seq_no64;
	};
} ipsec_aad_t;

/* Return IV length required for the cipher for IPsec use */
uint32_t _odp_ipsec_cipher_iv_len(odp_cipher_alg_t cipher);

/* Return digest length required for the cipher for IPsec use */
uint32_t _odp_ipsec_auth_digest_len(odp_auth_alg_t auth);

/* Return the maximum number of SAs supported by the implementation */
uint32_t _odp_ipsec_max_num_sa(void);

/*
 * Get SA entry from handle without obtaining a reference
 */
ipsec_sa_t *_odp_ipsec_sa_entry_from_hdl(odp_ipsec_sa_t sa);

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
 * Update SA lifetime counters, filling respective status for the packet.
 *
 * @retval <0 if hard limits were breached
 */
int _odp_ipsec_sa_lifetime_update(ipsec_sa_t *ipsec_sa, uint32_t len,
				  odp_ipsec_op_status_t *status);

/* Run pre-check on sequence number of the packet.
 *
 * @retval <0 if the packet falls out of window
 */
int _odp_ipsec_sa_replay_precheck(ipsec_sa_t *ipsec_sa, uint64_t seq,
				  odp_ipsec_op_status_t *status);

/* Run check on sequence number of the packet and update window if necessary.
 *
 * @retval <0 if the packet falls out of window
 */
int _odp_ipsec_sa_replay_update(ipsec_sa_t *ipsec_sa, uint64_t seq,
				odp_ipsec_op_status_t *status);

/**
  * Allocate an IPv4 ID for an outgoing packet.
  */
uint16_t _odp_ipsec_sa_alloc_ipv4_id(ipsec_sa_t *ipsec_sa);

/**
 * Try inline IPsec processing of provided packet.
 *
 * @retval 0 if packet was processed and will be queue using IPsec inline
 *           processing
 */
int _odp_ipsec_try_inline(odp_packet_t *pkt);

/**
 * Populate number of packets and bytes of data successfully processed by the SA
 * in the odp_ipsec_stats_t structure passed.
 *
 */
void _odp_ipsec_sa_stats_pkts(ipsec_sa_t *sa, odp_ipsec_stats_t *stats);

/**
  * Return true if IPsec operates in sync mode in the given direction.
  */
odp_bool_t _odp_ipsec_is_sync_mode(odp_ipsec_dir_t dir);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
