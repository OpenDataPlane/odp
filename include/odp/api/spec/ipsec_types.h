/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

/**
 * @file
 *
 * ODP IPsec API type definitions
 */

#ifndef ODP_API_SPEC_IPSEC_TYPES_H_
#define ODP_API_SPEC_IPSEC_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/classification.h>
#include <odp/api/crypto_types.h>
#include <odp/api/packet_io_types.h>
#include <odp/api/protocols.h>
#include <odp/api/std_types.h>
#include <odp/api/traffic_mngr.h>

/** @addtogroup odp_ipsec
 *  @{
 */

/**
 * @typedef odp_ipsec_sa_t
 * IPSEC Security Association (SA)
 */

 /**
 * @def ODP_IPSEC_SA_INVALID
 * Invalid IPSEC SA
 */

/**
 * IPSEC operation mode
 */
typedef enum odp_ipsec_op_mode_t {
	/** Synchronous IPSEC operation
	  *
	  * Application uses synchronous IPSEC operations,
	  * which output all results on function return.
	  */
	ODP_IPSEC_OP_MODE_SYNC = 0,

	/** Asynchronous IPSEC operation
	  *
	  * Application uses asynchronous IPSEC operations,
	  * which return results via events.
	  */
	ODP_IPSEC_OP_MODE_ASYNC,

	/** Inline IPSEC operation
	  *
	  * Packet input/output is connected directly to IPSEC inbound/outbound
	  * processing. Application uses asynchronous or inline IPSEC
	  * operations.
	  *
	  * Inline processed inbound packets are delivered to the application
	  * in the same way as packets processed by odp_ipsec_in_enq().
	  */
	ODP_IPSEC_OP_MODE_INLINE,

	/** IPSEC is disabled in inbound / outbound direction */
	ODP_IPSEC_OP_MODE_DISABLED

} odp_ipsec_op_mode_t;

/**
 * IPSEC TEST SA operation
 */
typedef enum odp_ipsec_test_sa_operation_t {
	/** Update next sequence number
	 *
	 * The seq_num parameter is an outbound SA specific parameter.
	 * Invoking the odp_ipsec_test_sa_update() API to update this
	 * field on an inbound SA will cause the API to return failure.
	 */
	ODP_IPSEC_TEST_SA_UPDATE_SEQ_NUM = 0,

	/** Update highest authenticated sequence number
	 *
	 * The antireplay_window_top parameter is inbound SA specific.
	 * Invoking the odp_ipsec_test_sa_update() API to update this
	 * field on an outbound SA will cause the API to return failure.
	 */
	ODP_IPSEC_TEST_SA_UPDATE_ANTIREPLAY_WINDOW_TOP

} odp_ipsec_test_sa_operation_t;

/**
 * IPSEC TEST SA parameter
 */
typedef union odp_ipsec_test_sa_param_t {
	/** Next sequence number
	 *
	 * @see ODP_IPSEC_TEST_SA_UPDATE_SEQ_NUM
	 */
	uint64_t seq_num;

	/** Highest authenticated sequence number
	 *
	 * @see ODP_IPSEC_TEST_SA_UPDATE_ANTIREPLAY_WINDOW_TOP
	 */
	uint64_t antireplay_window_top;

} odp_ipsec_test_sa_param_t;

/**
 * Configuration options for IPSEC inbound processing
 */
typedef struct odp_ipsec_inbound_config_t {
	/** Default destination queue for IPSEC events
	 *
	 *  When inbound SA lookup fails in the asynchronous mode,
	 *  resulting IPSEC events are enqueued into this queue.
	 */
	odp_queue_t default_queue;

	/** Constraints for SPI values used with inbound SA lookup. Minimal
	 *  SPI range and unique values may improve performance. */
	struct {
		/** Minimum SPI value for SA lookup. Default value is 0. */
		uint32_t min_spi;

		/** Maximum SPI value for SA lookup. Default value is
		 *  UINT32_MAX. */
		uint32_t max_spi;

		/** Select if SPI values for SA lookup are unique or may contain
		 *  the same SPI value multiple times. The default value is 0.
		 *
		 *  0: All SAs in SA lookup have unique SPI value
		 *  1: The same SPI value may be used for multiple SAs
		 */
		odp_bool_t spi_overlap;

	} lookup;

	/** Retain outer headers
	 *
	 *  Select up to which protocol layer (at least) outer headers are
	 *  retained in inbound inline processing. Default value is
	 *  ODP_PROTO_LAYER_NONE.
	 *
	 *  ODP_PROTO_LAYER_NONE: Application does not require any outer
	 *                        headers to be retained.
	 *
	 *  ODP_PROTO_LAYER_L2:   Retain headers up to layer 2.
	 *
	 *  ODP_PROTO_LAYER_L3:   Retain headers up to layer 3, otherwise the
	 *                        same as ODP_PROTO_LAYER_ALL.
	 *
	 *  ODP_PROTO_LAYER_L4:   Retain headers up to layer 4, otherwise the
	 *                        same as ODP_PROTO_LAYER_ALL.
	 *
	 *  ODP_PROTO_LAYER_ALL:  In tunnel mode, all headers before IPSEC are
	 *                        retained. In transport mode, all headers
	 *                        before IP (carrying IPSEC) are retained.
	 *
	 */
	odp_proto_layer_t retain_outer;

	/** Parse packet headers after IPSEC transformation
	 *
	 *  Select header parsing level after inbound processing. Headers of the
	 *  resulting packet must be checked (at least) up to this level.
	 *  Parsing starts from IP (layer 3). Packet metadata from IP to this
	 *  layer is set. In addition, offset (and pointer) to the next layer
	 *  is set. Other layer/protocol specific metadata have undefined
	 *  values.
	 *
	 *  Each successfully transformed packet has a valid value for L3 offset
	 *  regardless of the parse configuration. Default value is
	 *  ODP_PROTO_LAYER_NONE. ODP_PROTO_LAYER_L2 is not a valid value.
	 */
	odp_proto_layer_t parse_level;

	/** Flags to control IPSEC payload data checks up to the selected parse
	 *  level. Checksum checking status can be queried for each packet with
	 *  odp_packet_l3_chksum_status() and odp_packet_l4_chksum_status().
	 *  Default value for all bits is 0 (skip all checksum checks).
	 */
	odp_proto_chksums_t chksums;

	/** Post-IPsec reassembly configuration
	 *
	 *  This field provides global IPsec configuration parameters for
	 *  fragment reassembly. The enable flag does not turn on reassembly
	 *  but tells if reassembly may be enabled in SA parameters.
	 *
	 *  The enable flag may be set only if retain_outer is
	 *  ODP_PROTO_LAYER_NONE.
	 */
	odp_reass_config_t reassembly;

	/** Attempt reassembly after inbound IPsec processing in
	 *  odp_ipsec_in_enq(). Default value is false.
	 */
	odp_bool_t reass_async;

	/** Attempt reassembly after inline inbound IPsec processing.
	 *  Default value is false.
	 **/
	odp_bool_t reass_inline;

} odp_ipsec_inbound_config_t;

/**
 * Configuration options for IPSEC outbound processing
 */
typedef struct odp_ipsec_outbound_config_t {
	/** Flags to control L3/L4 checksum insertion as part of outbound
	 *  packet processing. These flags control checksum insertion (for the
	 *  payload packet) in the same way as the checksum flags in
	 *  odp_pktout_config_opt_t control checksum insertion when sending
	 *  packets out through a pktio interface. Also packet checksum override
	 *  functions (e.g. odp_packet_l4_chksum_insert()) can be used in
	 *  the same way.
	 */
	union {
		/** Mapping for individual bits */
		struct {
			/** Insert IPv4 header checksum on the payload packet
			 *  before IPSEC transformation. Default value is 0. */
			uint32_t inner_ipv4   : 1;

			/** Insert UDP header checksum on the payload packet
			 *  before IPSEC transformation. Default value is 0. */
			uint32_t inner_udp    : 1;

			/** Insert TCP header checksum on the payload packet
			 *  before IPSEC transformation. Default value is 0. */
			uint32_t inner_tcp    : 1;

			/** Insert SCTP header checksum on the payload packet
			 *  before IPSEC transformation. Default value is 0. */
			uint32_t inner_sctp   : 1;

		} chksum;

		/** All bits of the bit field structure
		  *
		  * This field can be used to set/clear all flags, or bitwise
		  * operations over the entire structure. */
		uint32_t all_chksum;
	};

} odp_ipsec_outbound_config_t;

/**
 * IPSEC TEST capability
 */
typedef struct odp_ipsec_test_capability_t {
	/** Parameters supported for sa_update */
	struct {
		/** Next sequence number value
		 *
		 * @see ODP_IPSEC_TEST_SA_UPDATE_SEQ_NUM
		 */
		odp_bool_t seq_num;

		/** Highest authenticated sequence number
		 *
		 * @see ODP_IPSEC_TEST_SA_UPDATE_ANTIREPLAY_WINDOW_TOP
		 */
		odp_bool_t antireplay_window_top;

	} sa_operations;

} odp_ipsec_test_capability_t;

/**
 * IPSEC capability
 */
typedef struct odp_ipsec_capability_t {
	/** Maximum number of IPSEC SAs */
	uint32_t max_num_sa;

	/** Synchronous IPSEC operation mode (ODP_IPSEC_OP_MODE_SYNC) support */
	odp_support_t op_mode_sync;

	/**
	 * Asynchronous IPSEC operation mode (ODP_IPSEC_OP_MODE_ASYNC) support
	 */
	odp_support_t op_mode_async;

	/**
	 * Inline inbound IPSEC operation mode (ODP_IPSEC_OP_MODE_INLINE)
	 * support
	 */
	odp_support_t op_mode_inline_in;

	/**
	 * Inline outgoing IPSEC operation mode (ODP_IPSEC_OP_MODE_INLINE)
	 * support
	 */
	odp_support_t op_mode_inline_out;

	/** IP Authenticated Header (ODP_IPSEC_AH) support */
	odp_support_t proto_ah;

	/** Fragment after IPsec support */
	odp_support_t frag_after;

	/** Fragment before IPsec support */
	odp_support_t frag_before;

	/**
	 * Support of pipelined classification (ODP_IPSEC_PIPELINE_CLS) of
	 *  resulting inbound packets
	 */
	odp_support_t pipeline_cls;

	/**
	 * Support of retaining outer headers (retain_outer) in inbound inline
	 * processed packets
	 */
	odp_support_t retain_header;

	/**
	 * Inner packet checksum check offload support in inbound direction.
	 */
	odp_proto_chksums_t chksums_in;

	/** Maximum number of different destination CoSes in classification
	 *  pipelining. The same CoS may be used for many SAs. This is equal or
	 *  less than 'max_cos' capability in classifier API.
	 */
	uint32_t max_cls_cos;

	/**
	 * Scheduled queue support
	 *
	 * 0: Scheduled queues are not supported either as IPsec SA destination
	 *    queues or as IPsec default queue
	 * 1: Scheduled queues are supported as both IPsec SA destination queues
	 *    and IPsec default queue
	 * @see odp_ipsec_sa_param_t
	 */
	odp_bool_t queue_type_sched;

	/**
	 * Plain queue support
	 *
	 * 0: Plain queues are not supported either as IPsec SA destination
	 *    queues or as IPsec default queue
	 * 1: Plain queues are supported as both IPsec SA destination queues and
	 *    IPsec default queue
	 * @see odp_ipsec_sa_param_t
	 */
	odp_bool_t queue_type_plain;

	/** Maximum number of different destination queues. The same queue may
	 *  be used for many SAs. */
	uint32_t max_queues;

	/** Support for returning completion packets as vectors */
	odp_pktin_vector_capability_t vector;

	/** Maximum anti-replay window size. */
	uint32_t max_antireplay_ws;

	/** Supported cipher algorithms */
	odp_crypto_cipher_algos_t ciphers;

	/** Supported authentication algorithms */
	odp_crypto_auth_algos_t   auths;

	/** Support of traffic manager (TM) after inline outbound IPSEC
	 *  processing. On unsupported platforms, application is not allowed
	 *  to use a TM enabled pktio (ODP_PKTOUT_MODE_TM) with outbound
	 *  inline IPSEC.
	 *
	 *  @see odp_pktio_open(), odp_pktio_param_t
	 */
	odp_support_t inline_ipsec_tm;

	/** IPSEC TEST capabilities
	 *
	 * @see odp_ipsec_test_sa_update()
	 */
	odp_ipsec_test_capability_t test;

	/** Post-IPsec reassembly capability */
	odp_reass_capability_t reassembly;

	/** Support of reassembly after inbound processing in odp_ipsec_in_enq() */
	odp_bool_t reass_async;

	/** Support of reassembly after inline inbound IPsec processing */
	odp_bool_t reass_inline;

} odp_ipsec_capability_t;

/**
 * Cipher algorithm capabilities
 */
typedef struct odp_ipsec_cipher_capability_t {
	/** Key length in bytes */
	uint32_t key_len;

} odp_ipsec_cipher_capability_t;

/**
 * Authentication algorithm capabilities
 */
typedef struct odp_ipsec_auth_capability_t {
	/** Key length in bytes */
	uint32_t key_len;

	/** ICV length in bytes */
	uint32_t icv_len;
} odp_ipsec_auth_capability_t;

/**
 * IPSEC configuration options
 */
typedef struct odp_ipsec_config_t {
	/** Inbound IPSEC operation mode. Application selects which mode
	 *  will be used for inbound IPSEC operations.
	 *
	 *  @see odp_ipsec_in(), odp_ipsec_in_enq()
	 */
	odp_ipsec_op_mode_t inbound_mode;

	/** Outbound IPSEC operation mode. Application selects which mode
	 *  will be used for outbound IPSEC operations.
	 *
	 *  @see odp_ipsec_out(), odp_ipsec_out_enq(), odp_ipsec_out_inline()
	 */
	odp_ipsec_op_mode_t outbound_mode;

	/** Maximum number of IPSEC SAs that application will use
	 * simultaneously */
	uint32_t max_num_sa;

	/** IPSEC inbound processing configuration */
	odp_ipsec_inbound_config_t inbound;

	/** IPSEC outbound processing configuration */
	odp_ipsec_outbound_config_t outbound;

	/** Enable stats collection
	 *
	 *  Default value is false (stats collection disabled).
	 *
	 *  @see odp_ipsec_stats(), odp_ipsec_stats_multi()
	 */
	odp_bool_t stats_en;

	/**
	 * Packet vector configuration for async and inline operations
	 *
	 * This packet vector configuration affects packets delivered to
	 * the application through the default queue and the SA destination
	 * queues. It does not affect packets delivered through pktio
	 * input queues.
	 */
	odp_pktin_vector_config_t vector;

} odp_ipsec_config_t;

/**
 * IPSEC SA direction
 */
typedef enum odp_ipsec_dir_t {
	/** Inbound IPSEC SA */
	ODP_IPSEC_DIR_INBOUND = 0,

	/** Outbound IPSEC SA */
	ODP_IPSEC_DIR_OUTBOUND

} odp_ipsec_dir_t;

/**
 * IPSEC protocol mode
 */
typedef enum odp_ipsec_mode_t {
	/** IPSEC tunnel mode */
	ODP_IPSEC_MODE_TUNNEL = 0,

	/** IPSEC transport mode */
	ODP_IPSEC_MODE_TRANSPORT

} odp_ipsec_mode_t;

/**
 * IPSEC protocol
 */
typedef enum odp_ipsec_protocol_t {
	/** ESP protocol */
	ODP_IPSEC_ESP = 0,

	/** AH protocol */
	ODP_IPSEC_AH

} odp_ipsec_protocol_t;

/**
 * IPSEC tunnel type
 */
typedef enum odp_ipsec_tunnel_type_t {
	/** Outer header is IPv4 */
	ODP_IPSEC_TUNNEL_IPV4 = 0,

	/** Outer header is IPv6 */
	ODP_IPSEC_TUNNEL_IPV6

} odp_ipsec_tunnel_type_t;

/**
 * IPSEC crypto parameters
 */
typedef struct odp_ipsec_crypto_param_t {
	/** Cipher algorithm
	 *
	 *  Select cipher algorithm to be used. ODP_CIPHER_ALG_NULL indicates
	 *  that ciphering is disabled. See 'ciphers' field of
	 *  odp_ipsec_capability_t for supported cipher algorithms. Algorithm
	 *  descriptions can be found from odp_cipher_alg_t documentation. Note
	 *  that some algorithms restrict choice of the pairing authentication
	 *  algorithm. When ciphering is enabled, cipher key and potential extra
	 *  key material (cipher_key_extra) need to be set. The default value
	 *  is ODP_CIPHER_ALG_NULL.
	 */
	odp_cipher_alg_t cipher_alg;

	/** Cipher key */
	odp_crypto_key_t cipher_key;

	/** Extra keying material for cipher algorithm
	 *
	 *  Additional data used as salt or nonce if the algorithm requires it,
	 *  other algorithms ignore this field. These algorithms require this
	 *  field to be set:
	 *  - ODP_CIPHER_ALG_AES_CTR: 4 bytes of nonce
	 *  - ODP_CIPHER_ALG_AES_GCM: 4 bytes of salt
	 *  - ODP_CIPHER_ALG_AES_CCM: 3 bytes of salt
	 *  - ODP_CIPHER_ALG_CHACHA20_POLY1305: 4 bytes of salt
	 */
	odp_crypto_key_t cipher_key_extra;

	/** Authentication algorithm
	 *
	 *  Select authentication algorithm to be used. ODP_AUTH_ALG_NULL
	 *  indicates that authentication is disabled. See 'auths' field of
	 *  odp_ipsec_capability_t for supported authentication algorithms.
	 *  Algorithm descriptions can be found from odp_auth_alg_t
	 *  documentation. Note that some algorithms restrict choice of the
	 *  pairing cipher algorithm. When single algorithm provides both
	 *  ciphering and authentication (i.e. Authenticated Encryption),
	 *  authentication side key information ('auth_key' and
	 *  'auth_key_extra') is ignored, and cipher side values are
	 *  used instead. These algorithms ignore authentication side key
	 *  information: ODP_AUTH_ALG_AES_GCM, ODP_AUTH_ALG_AES_CCM and
	 *  ODP_AUTH_ALG_CHACHA20_POLY1305. Otherwise, authentication side
	 *  parameters must be set when authentication is enabled. The default
	 *  value is ODP_AUTH_ALG_NULL.
	 */
	odp_auth_alg_t auth_alg;

	/** Authentication key */
	odp_crypto_key_t auth_key;

	/** Extra keying material for authentication algorithm
	 *
	 *  Additional data used as salt or nonce if the algorithm requires it,
	 *  other algorithms ignore this field. These algorithms require this
	 *  field to be set:
	 *  - ODP_AUTH_ALG_AES_GMAC: 4 bytes of salt
	 */
	odp_crypto_key_t auth_key_extra;

	/**
	 * Length of integrity check value (ICV) in bytes.
	 *
	 * Some algorithms support multiple ICV lengths when used with IPsec.
	 * This field can be used to select a non-default ICV length.
	 *
	 * Zero value indicates that the default ICV length shall be used.
	 * The default length depends on the selected algorithm as follows:
	 *
	 * Algorithm                       Default length     Other lengths
	 * ----------------------------------------------------------------
	 * ODP_AUTH_ALG_NULL               0
	 * ODP_AUTH_ALG_MD5_HMAC           12
	 * ODP_AUTH_ALG_SHA1_HMAC          12
	 * ODP_AUTH_ALG_SHA256_HMAC        16
	 * ODP_AUTH_ALG_SHA384_HMAC        24
	 * ODP_AUTH_ALG_SHA512_HMAC        32
	 * ODP_AUTH_ALG_AES_GCM            16                 8, 12
	 * ODP_AUTH_ALG_AES_GMAC           16
	 * ODP_AUTH_ALG_AES_CCM            16                 8, 12
	 * ODP_AUTH_ALG_AES_CMAC           12
	 * ODP_AUTH_ALG_AES_XCBC_MAC       12
	 * ODP_AUTH_ALG_CHACHA20_POLY1305  16
	 *
	 * The requested ICV length must be supported for the selected
	 * algorithm as indicated by odp_ipsec_auth_capability().
	 *
	 * The default value is 0.
	 */
	uint32_t icv_len;

} odp_ipsec_crypto_param_t;

/** IPv4 header parameters */
typedef struct odp_ipsec_ipv4_param_t {
	/** IPv4 source address (NETWORK ENDIAN) */
	void *src_addr;

	/** IPv4 destination address (NETWORK ENDIAN) */
	void *dst_addr;

	/** IPv4 Differentiated Services Code Point. The default value is 0. */
	uint8_t dscp;

	/** IPv4 Don't Fragment bit. The default value is 0. */
	uint8_t df;

	/** IPv4 Time To Live. The default value is 255. */
	uint8_t ttl;

} odp_ipsec_ipv4_param_t;

/** IPv6 header parameters */
typedef struct odp_ipsec_ipv6_param_t {
	/** IPv6 source address (NETWORK ENDIAN) */
	void *src_addr;

	/** IPv6 destination address (NETWORK ENDIAN) */
	void *dst_addr;

	/** IPv6 flow label. The default value is 0. */
	uint32_t flabel;

	/** IPv6 Differentiated Services Code Point. The default value is 0. */
	uint8_t dscp;

	/** IPv6 hop limit. The default value is 255. */
	uint8_t hlimit;

} odp_ipsec_ipv6_param_t;

/**
 * IPSEC tunnel parameters
 *
 * These parameters are used to build outbound tunnel headers. All values are
 * passed in CPU native byte / bit order if not specified otherwise.
 * IP addresses must be in NETWORK byte order as those are passed in with
 * pointers and copied byte-by-byte from memory to the packet.
 */
typedef struct odp_ipsec_tunnel_param_t {
	/** Tunnel type: IPv4 or IPv6. The default is IPv4. */
	odp_ipsec_tunnel_type_t type;

	/** Tunnel type specific parameters */
	struct {
		/** IPv4 header parameters */
		odp_ipsec_ipv4_param_t ipv4;

		/** IPv6 header parameters */
		odp_ipsec_ipv6_param_t ipv6;
	};
} odp_ipsec_tunnel_param_t;

/**
 * IPSEC SA option flags
 */
typedef struct odp_ipsec_sa_opt_t {
	/** Extended Sequence Numbers (ESN)
	  *
	  * * 1: Use extended (64 bit) sequence numbers
	  * * 0: Use normal sequence numbers (the default value)
	  */
	uint32_t esn : 1;

	/** UDP encapsulation
	  *
	  * * 1: Do UDP encapsulation/decapsulation so that IPSEC packets can
	  *      traverse through NAT boxes.
	  * * 0: No UDP encapsulation (the default value)
	  */
	uint32_t udp_encap : 1;

	/** Copy DSCP bits
	  *
	  * * 1: Copy IPv4 or IPv6 DSCP bits from inner IP header to
	  *      the outer IP header in encapsulation, and vice versa in
	  *      decapsulation.
	  * * 0: Use values from odp_ipsec_tunnel_param_t in encapsulation and
	  *      do not change DSCP field in decapsulation (the default value).
	  */
	uint32_t copy_dscp : 1;

	/** Copy IPv6 Flow Label
	  *
	  * * 1: Copy IPv6 flow label from inner IPv6 header to the
	  *      outer IPv6 header.
	  * * 0: Use value from odp_ipsec_tunnel_param_t (the default value)
	  */
	uint32_t copy_flabel : 1;

	/** Copy IPv4 Don't Fragment bit
	  *
	  * * 1: Copy the DF bit from the inner IPv4 header to the outer
	  *      IPv4 header.
	  * * 0: Use value from odp_ipsec_tunnel_param_t (the default value)
	  */
	uint32_t copy_df : 1;

	/** Decrement inner packet Time To Live (TTL) field
	  *
	  * * 1: In tunnel mode, decrement inner packet IPv4 TTL or
	  *      IPv6 Hop Limit after tunnel decapsulation, or before tunnel
	  *      encapsulation.
	  * * 0: Inner packet is not modified (the default value)
	  */
	uint32_t dec_ttl : 1;

} odp_ipsec_sa_opt_t;

/**
 * IPSEC SA lifetime limits
 *
 * These limits are used for setting up SA lifetime. IPSEC operations check
 * against the limits and output a status code (e.g. soft_exp_bytes) when
 * a limit is crossed. It's implementation defined how many times soft
 * lifetime expiration is reported: only once, first N or all packets following
 * the limit crossing. Any number of limits may be used simultaneously.
 * Use zero when there is no limit.
 *
 * The default value is zero (i.e. no limit) for all the limits.
 */
typedef struct odp_ipsec_lifetime_t {
	/** Soft expiry limits for the session */
	struct {
		/** Limit in bytes */
		uint64_t bytes;

		/** Limit in packet */
		uint64_t packets;
	} soft_limit;

	/** Hard expiry limits for the session */
	struct {
		/** Limit in bytes */
		uint64_t bytes;

		/** Limit in packet */
		uint64_t packets;
	} hard_limit;
} odp_ipsec_lifetime_t;

/**
 * Fragmentation mode
 *
 * These options control outbound IP packet fragmentation offload. When offload
 * is enabled, IPSEC operation will determine if fragmentation is needed and
 * does it according to the mode.
 */
typedef enum odp_ipsec_frag_mode_t {
	/** Do not fragment IP packets */
	ODP_IPSEC_FRAG_DISABLED = 0,

	/** Fragment IP packet before IPSEC operation */
	ODP_IPSEC_FRAG_BEFORE,

	/** Fragment IP packet after IPSEC operation */
	ODP_IPSEC_FRAG_AFTER,

	/** Only check if IP fragmentation is needed,
	  * do not fragment packets. */
	ODP_IPSEC_FRAG_CHECK
} odp_ipsec_frag_mode_t;

/**
 * Packet lookup mode
 *
 * Lookup mode controls how an SA participates in SA lookup offload.
 * Inbound operations perform SA lookup if application does not provide a SA as
 * a parameter. In inline mode, a lookup miss directs the packet back to normal
 * packet input interface processing. SA lookup failure status
 * (status.error.sa_lookup) is reported through odp_ipsec_packet_result_t.
 */
typedef enum odp_ipsec_lookup_mode_t {
	/** Inbound SA lookup is disabled for the SA. */
	ODP_IPSEC_LOOKUP_DISABLED = 0,

	/** Inbound SA lookup is enabled. Lookup matches only SPI value. */
	ODP_IPSEC_LOOKUP_SPI,

	/** Inbound SA lookup is enabled. Lookup matches both SPI value and
	  * destination IP address. Functionality is otherwise identical to
	  * ODP_IPSEC_LOOKUP_SPI. */
	ODP_IPSEC_LOOKUP_DSTADDR_SPI

} odp_ipsec_lookup_mode_t;

/**
 * IPSEC pipeline configuration
 */
typedef enum odp_ipsec_pipeline_t {
	/** Do not pipeline. Send all resulting events to the application. */
	ODP_IPSEC_PIPELINE_NONE = 0,

	/** Send resulting packets to the classifier
	 *
	 *  IPSEC capability 'pipeline_cls' determines if pipelined
	 *  classification is supported. */
	ODP_IPSEC_PIPELINE_CLS

} odp_ipsec_pipeline_t;

/**
 * IPSEC header type
 */
typedef enum odp_ipsec_ip_version_t {
	/** Header is IPv4 */
	ODP_IPSEC_IPV4 = 4,

	/** Header is IPv6 */
	ODP_IPSEC_IPV6 = 6

} odp_ipsec_ip_version_t;

/**
 * IPSEC Security Association (SA) parameters
 */
typedef struct odp_ipsec_sa_param_t {
	/** IPSEC SA direction: inbound or outbound */
	odp_ipsec_dir_t dir;

	/** IPSEC protocol: ESP or AH. The default value is ODP_IPSEC_ESP. */
	odp_ipsec_protocol_t proto;

	/** IPSEC protocol mode: transport or tunnel */
	odp_ipsec_mode_t mode;

	/** Parameters for crypto and authentication algorithms */
	odp_ipsec_crypto_param_t crypto;

	/** Various SA option flags */
	odp_ipsec_sa_opt_t opt;

	/** SA lifetime parameters */
	odp_ipsec_lifetime_t lifetime;

	/** SPI value */
	uint32_t spi;

	/** Destination queue for IPSEC events
	 *
	 *  Operations in asynchronous or inline mode enqueue resulting events
	 *  into this queue. The default queue ('default_queue') is used when
	 *  SA is not known.
	 */
	odp_queue_t dest_queue;

	/** User defined SA context pointer
	 *
	 *  User defined context pointer associated with the SA.
	 *  The implementation may prefetch the context data. Default value
	 *  of the pointer is NULL.
	 */
	void *context;

	/** Context data length
	 *
	 *  User defined context data length in bytes for prefetching.
	 *  The implementation may use this value as a hint for the number of
	 *  context data bytes to prefetch. Default value is zero (no hint).
	 */
	uint32_t context_len;

	/** IPSEC SA direction dependent parameters */
	struct {
		/** Inbound specific parameters */
		struct {
			/** SA lookup mode
			 *  The default value is ODP_IPSEC_LOOKUP_DISABLED.
			 */
			odp_ipsec_lookup_mode_t lookup_mode;

			/** Additional SA lookup parameters. Values are
			 *  considered only in ODP_IPSEC_LOOKUP_DSTADDR_SPI
			 *  lookup mode. */
			struct {
				/** Select IP version */
				odp_ipsec_ip_version_t ip_version;

				/** IP destination address (NETWORK ENDIAN) to
				 *  be matched in addition to SPI value. */
				void *dst_addr;

			} lookup_param;

			/** Minimum anti-replay window size. Use 0 to disable
			 *  anti-replay service. The default value is 0.
			 */
			uint32_t antireplay_ws;

			/** Select pipelined destination for resulting events
			 *
			 * Asynchronous and inline modes generate events.
			 * Select where those events are sent. Inbound SAs may
			 * choose to use pipelined classification. The default
			 * value is ODP_IPSEC_PIPELINE_NONE.
			 */
			odp_ipsec_pipeline_t pipeline;

			/** Classifier destination CoS for resulting packets
			 *
			 *  Successfully decapsulated packets are sent to
			 *  classification through this CoS. Other resulting
			 *  events are sent to 'dest_queue'. This field is
			 *  considered only when 'pipeline' is
			 *  ODP_IPSEC_PIPELINE_CLS. The CoS must not be shared
			 *  between any pktio interface default CoS. The maximum
			 *  number of different CoS supported is defined by
			 *  IPSEC capability max_cls_cos.
			 */
			odp_cos_t dest_cos;

			/** Enable reassembly of IPsec tunneled fragments
			 *
			 *  Attempt reassembly of fragments after IPsec tunnel
			 *  decapsulation.
			 *
			 *  Reassembly is attempted for inline or asynchronously
			 *  processed packets, not for packets processed using
			 *  the synchronous API function.
			 *
			 *  Fragments received through different SAs will not be
			 *  reassembled into the same packet.
			 *
			 *  IPsec statistics reflect IPsec processing before
			 *  reassembly and thus count all individual fragments.
			 *
			 *  Reassembly may be enabled for an SA only if
			 *  reassembly was enabled in the global IPsec
			 *  configuration.
			 *
			 *  Default value is false.
			 *
			 *  @see odp_ipsec_config()
			 *
			 */
			odp_bool_t reassembly_en;

		} inbound;

		/** Outbound specific parameters */
		struct {
			/** Parameters for tunnel mode */
			odp_ipsec_tunnel_param_t tunnel;

			/** Fragmentation mode
			 *  The default value is ODP_IPSEC_FRAG_DISABLED.
			 */
			odp_ipsec_frag_mode_t frag_mode;

			/** MTU for outbound IP fragmentation offload
			 *
			 *  This is the maximum length of IP packets that
			 *  outbound IPSEC operations may produce. The value may
			 *  be updated later with odp_ipsec_sa_mtu_update().
			 */
			uint32_t mtu;

		} outbound;
	};

} odp_ipsec_sa_param_t;

/**
 * IPSEC stats content
 */
typedef struct odp_ipsec_stats_t {
	/** Number of packets processed successfully */
	uint64_t success;

	/** Number of packets with protocol errors */
	uint64_t proto_err;

	/** Number of packets with authentication errors */
	uint64_t auth_err;

	/** Number of packets with antireplay check failures */
	uint64_t antireplay_err;

	/** Number of packets with algorithm errors */
	uint64_t alg_err;

	/** Number of packets with MTU errors */
	uint64_t mtu_err;

	/** Number of packets with hard lifetime(bytes) expired */
	uint64_t hard_exp_bytes_err;

	/** Number of packets with hard lifetime(packets) expired */
	uint64_t hard_exp_pkts_err;

	/** Total bytes of packet data processed by IPsec SA in success cases
	 *
	 * The range of packet bytes included in the success_bytes count is
	 * implementation defined but includes at least the bytes input for
	 * encryption or bytes output after decryption in ESP or the bytes
	 * authenticated in AH.
	 */
	uint64_t success_bytes;
} odp_ipsec_stats_t;

/**
 * IPSEC SA information
 */
typedef struct odp_ipsec_sa_info_t {
	/** IPsec SA parameters
	 *
	 * This is not necessarily an exact copy of the actual parameter
	 * structure used in SA creation. The fields that were relevant
	 * for the SA in the creation phase will have the same values,
	 * but other fields, such as tunnel parameters for a transport
	 * mode SA, will have undefined values.
	 */
	odp_ipsec_sa_param_t param;

	/** IPSEC SA direction dependent parameters */
	union {
		/** Inbound specific parameters */
		struct {
			/** Additional SA lookup parameters. */
			struct {
				/** IP destination address (NETWORK ENDIAN) to
				 *  be matched in addition to SPI value. */
				uint8_t dst_addr[ODP_IPV6_ADDR_SIZE];
			} lookup_param;

			/** Antireplay window size
			 *
			 * Antireplay window size configured for the SA.
			 * This value can be different from what application
			 * had requested.
			 */
			uint32_t antireplay_ws;

			/** Antireplay window top
			 *
			 * Sequence number representing a recent top of the
			 * anti-replay window. There may be a delay before the
			 * SA state is reflected in the value. The value will be
			 * zero if no packets have been processed or if the
			 * anti-replay service is not enabled.
			 */
			uint64_t antireplay_window_top;
		} inbound;

		/** Outbound specific parameters */
		struct {
			/** Sequence number
			 *
			 * Sequence number used for a recently processed packet.
			 * There may be a delay before the SA state is reflected
			 * in the value. When no packets have been processed,
			 * the value will be zero.
			 */
			uint64_t seq_num;

			/** Tunnel IP address */
			union {
				/** IPv4 */
				struct {
					/** IPv4 source address */
					uint8_t src_addr[ODP_IPV4_ADDR_SIZE];
					/** IPv4 destination address */
					uint8_t dst_addr[ODP_IPV4_ADDR_SIZE];
				} ipv4;

				/** IPv6 */
				struct {
					/** IPv6 source address */
					uint8_t src_addr[ODP_IPV6_ADDR_SIZE];
					/** IPv6 destination address */
					uint8_t dst_addr[ODP_IPV6_ADDR_SIZE];
				} ipv6;
			} tunnel;
		} outbound;
	};
} odp_ipsec_sa_info_t;

/** IPSEC operation status has no errors */
#define ODP_IPSEC_OK 0

/** IPSEC errors */
typedef struct odp_ipsec_error_t {
	/** IPSEC errors */
	union {
		/** Error bits */
		struct {
			/** Protocol error. Not a valid ESP or AH packet,
			 *  packet data length error, etc. */
			uint32_t proto            : 1;

			/** SA lookup failed */
			uint32_t sa_lookup        : 1;

			/** Authentication failed */
			uint32_t auth             : 1;

			/** Anti-replay check failed */
			uint32_t antireplay       : 1;

			/** Other algorithm error */
			uint32_t alg              : 1;

			/** Packet does not fit into the given MTU size */
			uint32_t mtu              : 1;

			/** Hard lifetime expired: bytes */
			uint32_t hard_exp_bytes   : 1;

			/** Hard lifetime expired: packets */
			uint32_t hard_exp_packets : 1;
		};

		/** All error bits
		 *
		 *  This field can be used to set, clear or compare
		 *  multiple bits. For example, 'status.error.all != 0'
		 *  checks if there are any errors.
		 */
		uint32_t all;
	};

} odp_ipsec_error_t;

/** IPSEC warnings */
typedef struct odp_ipsec_warn_t {
	/** IPSEC warnings */
	union {
		/** Warning bits */
		struct {
			/** Soft lifetime expired: bytes */
			uint32_t soft_exp_bytes   : 1;

			/** Soft lifetime expired: packets */
			uint32_t soft_exp_packets : 1;
		};

		/** All warning bits
		 *
		 *  This field can be used to set/clear all bits, or to perform
		 *  bitwise operations over those. */
		uint32_t all;
	};

} odp_ipsec_warn_t;

/** IPSEC operation status */
typedef struct odp_ipsec_op_status_t {
	/** IPSEC status bits */
	union {
		/** IPSEC errors and warnings */
		struct {
			/** IPSEC errors */
			odp_ipsec_error_t error;

			/** IPSEC warnings */
			odp_ipsec_warn_t warn;
		};

		/** All status bits. Combines all error and warning bits.
		 *  For example, 'status.all != ODP_IPSEC_OK' checks if there
		 *  are any errors or warnings. */
		uint64_t all;

	};

} odp_ipsec_op_status_t;

/** IPSEC operation flags */
typedef struct odp_ipsec_op_flag_t {
	/** IPSEC operations flags */
	union {
		/** Operation flags */
		struct {
			/** Packet was processed in inline mode */
			uint32_t inline_mode      : 1;

		};

		/** All flag bits
		 *
		 *  This field can be used to set/clear all flags, or to perform
		 *  bitwise operations over those. */
		uint32_t all;
	};

} odp_ipsec_op_flag_t;

/**
 * IPSEC outbound operation options
 *
 * These may be used to override some SA level options
 */
typedef struct odp_ipsec_out_opt_t {
	/** Union of all flag bits */
	union {
		/** Option flags. Set flag for those options that are
		 *  used, all other options are ignored. */
		struct {
			/** Use fragmentation mode option */
			uint32_t frag_mode: 1;

			/** Use TFC padding length option */
			uint32_t tfc_pad:   1;

			/** Tunnel mode TFC dummy packet. This can be used only
			 *  in tunnel mode. When the flag is set, packet length
			 *  and content is ignored and instead a TFC dummy
			 *  packet is created during IPSEC operation. The dummy
			 *  packet length is defined by 'tfc_pad_len' option.
			 *  If the SA is configured to copy IP header fields
			 *  from inner IP packet, those fields must be passed
			 *  with IP parameters option. */
			uint32_t tfc_dummy: 1;

			/** Use IP parameters option */
			uint32_t ip_param:  1;

		} flag;

		/** All flag bits
		 *
		 *  This field can be used to set/clear all flags, or to perform
		 *  bitwise operations over those. */
		uint32_t all_flags;
	};

	/** Fragmentation mode */
	odp_ipsec_frag_mode_t frag_mode;

	/** TFC padding length
	 *
	 *  Number of TFC padding bytes added to the packet during IPSEC
	 *  processing. Resulting packet should not exceed the maximum packet
	 *  length of the pool, otherwise IPSEC operation may fail.
	 *  Implementation guarantees that the padding does not contain any
	 *  confidential information. */
	uint32_t tfc_pad_len;

	/** Union of IP parameters */
	union {
		/** Override IPv4 parameters in outer header creation.
		 *  IP addresses are ignored. */
		odp_ipsec_ipv4_param_t ipv4;

		/** Override IPv6 parameters in outer header creation.
		 *  IP addresses are ignored. */
		odp_ipsec_ipv6_param_t ipv6;
	};

} odp_ipsec_out_opt_t;

/**
 * IPSEC outbound operation parameters
 */
typedef struct odp_ipsec_out_param_t {
	/** Number of SAs
	 *
	 *  Outbound IPSEC operation needs SA from application. Use either
	 *  single SA for all packets, or a SA per packet.
	 *
	 *  Valid values are:
	 *  - 1:  Single SA for all packets
	 *  - N:  A SA per packet. N must match the number of packets.
	 */
	int num_sa;

	/** Number of outbound operation options
	 *
	 *  Valid values are:
	 *  - 0:  No options
	 *  - 1:  Single option for all packets
	 *  - N:  An option per packet. N must match the number of packets.
	 */
	int num_opt;

	/** Pointer to an array of IPSEC SAs */
	const odp_ipsec_sa_t *sa;

	/** Pointer to an array of outbound operation options
	 *
	 *  May be NULL when num_opt is zero.
	 */
	const odp_ipsec_out_opt_t *opt;

} odp_ipsec_out_param_t;

/**
 * IPSEC inbound operation parameters
 */
typedef struct odp_ipsec_in_param_t {
	/** Number of SAs
	 *
	 *  Inbound IPSEC operation processes a packet using the SA provided by
	 *  the application. If the application does not provide an SA, the
	 *  operation searches for the SA by matching the input packet with all
	 *  inbound SAs according to the lookup mode (odp_ipsec_lookup_mode_t)
	 *  configured in each SA. When passing SAs, use either single SA for
	 *  all packets, or a SA per packet.
	 *
	 *  Valid values are:
	 *  - 0:  No SAs. SA lookup is done for all packets.
	 *  - 1:  Single SA for all packets
	 *  - N:  A SA per packet. N must match the number of packets.
	 */
	int num_sa;

	/** Pointer to an array of IPSEC SAs
	 *
	 *  May be NULL when num_sa is zero.
	 */
	const odp_ipsec_sa_t *sa;

} odp_ipsec_in_param_t;

/**
 * Outbound inline IPSEC operation parameters
 */
typedef struct odp_ipsec_out_inline_param_t {
	/** Packet output interface for inline outbound operation without TM
	 *
	 *  Outbound inline IPSEC operation uses this packet IO interface to
	 *  output the packet after a successful IPSEC transformation. The pktio
	 *  must have been configured to operate in inline IPSEC mode.
	 *
	 *  The pktio must not have been configured with ODP_PKTOUT_MODE_TM.
	 *  For IPSEC inline output to TM enabled interfaces set this field
	 *  to ODP_PKTIO_INVALID and specify the TM queue to be used through
	 *  the tm_queue parameter. Inline IPSEC output through TM can be
	 *  done only if the platform has inline_ipsec_tm capability.
	 */
	odp_pktio_t pktio;

	/** TM queue for inline outbound operation
	 *
	 *  TM queue to be used for inline IPSEC output when pktio field
	 *  is ODP_PKTIO_INVALID, indicating use of TM. Otherwise ignored.
	 *
	 *  @see odp_ipsec_capability()
	 */
	odp_tm_queue_t tm_queue;

	/** Outer headers for inline output operation
	 *
	 *  Outbound inline IPSEC operation uses this information to prepend
	 *  outer headers to the IPSEC packet before sending it out.
	 */
	struct {
		/** Points to first byte of outer headers to be copied in
		 *  front of the outgoing IPSEC packet. Implementation copies
		 *  the headers during odp_ipsec_out_inline() call.
		 *
		 *  Null value indicates that the outer headers are in the
		 *  packet data, starting at L2 offset and ending at the byte
		 *  before L3 offset. In this case, value of 'len' field must
		 *  be greater than zero and set to L3 offset minus L2 offset.
		 */
		const uint8_t *ptr;

		/** Outer header length in bytes */
		uint32_t len;
	} outer_hdr;

} odp_ipsec_out_inline_param_t;

/**
 * IPSEC operation result for a packet
 */
typedef struct odp_ipsec_packet_result_t {
	/** IPSEC operation status. Use this to check if IPSEC operation
	 *  reported any errors or warnings (e.g. status.all != ODP_IPSEC_OK).
	 */
	odp_ipsec_op_status_t status;

	/** IPSEC operation flags */
	odp_ipsec_op_flag_t flag;

	/** IPSEC SA that was used to create the packet
	 *
	 *  Operation updates this SA handle value, when SA look up is performed
	 *  as part of the operation and the look up is successful. Operation
	 *  status code indicates if the look up failed. Otherwise, the SA
	 *  provided by the application is copied here.
	 */
	odp_ipsec_sa_t sa;

	/** Packet outer header status before inbound inline processing.
	 *  This is valid only when outer headers are retained
	 *  (see odp_ipsec_inbound_config_t) and flag.inline_mode is set.
	 */
	struct {
		/** Points to the first byte of retained outer headers. These
		 *  headers are stored in a contiquous, per packet,
		 *  implementation specific memory space. Since the memory space
		 *  may overlap with e.g. packet head/tailroom, the content
		 *  becomes invalid if packet data storage is modified in
		 *  any way. The memory space may not be shareable to other
		 *  threads. */
		uint8_t *ptr;

		/** Outer header length in bytes */
		uint32_t len;
	} outer_hdr;

	/** Total IP length of the original ESP or AH packet before IPsec
	 *  decapsulation. This is valid only for inbound inline and async
	 *  processed packets. Zero value means that the length information
	 *  is not available.
	 *
	 *  If the result packet was reassembled from multiple IPsec
	 *  protected packets, this is the sum of the lengths of all the
	 *  involved IPsec packets.
	 */
	uint32_t orig_ip_len;

} odp_ipsec_packet_result_t;

/**
 * IPSEC status ID
 */
typedef enum odp_ipsec_status_id_t {
	/** Response to SA disable command
	 *
	 *  Following status event (odp_ipsec_status_t) fields have valid
	 *  content, other fields must be ignored:
	 *  - sa:       The SA that was requested to be disabled
	 *  - result:   Operation result
	 */
	ODP_IPSEC_STATUS_SA_DISABLE = 0,

	/** Warning from inline IPSEC processing
	 *
	 *  Following status event (odp_ipsec_status_t) fields have valid
	 *  content, other fields must be ignored:
	 *  - sa:       The SA that caused the warning
	 *  - warn:     The warning(s) reported by this event
	 *
	 *  This status event is generated only for outbound SAs in
	 *  ODP_IPSEC_OP_MODE_INLINE mode.
	 */
	ODP_IPSEC_STATUS_WARN

} odp_ipsec_status_id_t;

/**
 * IPSEC status content
 */
typedef struct odp_ipsec_status_t {
	/** IPSEC status ID */
	odp_ipsec_status_id_t id;

	/** IPSEC SA that was target of the operation */
	odp_ipsec_sa_t sa;

	/** Result of the operation
	 *
	 *   0:    Success
	 *  <0:    Failure
	 */
	int result;

	/** Warnings of an ODP_IPSEC_STATUS_WARN status event */
	odp_ipsec_warn_t warn;

} odp_ipsec_status_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
