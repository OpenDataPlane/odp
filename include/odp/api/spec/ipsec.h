/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP IPSEC API
 */

#ifndef ODP_API_IPSEC_H_
#define ODP_API_IPSEC_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/crypto.h>
#include <odp/api/support.h>
#include <odp/api/packet_io.h>
#include <odp/api/classification.h>

/** @defgroup odp_ipsec ODP IPSEC
 *  Operations of IPSEC API.
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
	  */
	ODP_IPSEC_OP_MODE_INLINE,

	/** IPSEC is disabled in inbound / outbound direction */
	ODP_IPSEC_OP_MODE_DISABLED

} odp_ipsec_op_mode_t;

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

	/** Maximum number of different destination CoSes in classification
	 *  pipelining. The same CoS may be used for many SAs. This is equal or
	 *  less than 'max_cos' capability in classifier API.
	 */
	uint32_t max_cls_cos;

	/** Maximum number of different destination queues. The same queue may
	 *  be used for many SAs. */
	uint32_t max_queues;

	/** Maximum anti-replay window size. */
	uint32_t max_antireplay_ws;

	/** Supported cipher algorithms */
	odp_crypto_cipher_algos_t ciphers;

	/** Supported authentication algorithms */
	odp_crypto_auth_algos_t   auths;

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
	/** Cipher algorithm */
	odp_cipher_alg_t cipher_alg;

	/** Cipher key */
	odp_crypto_key_t cipher_key;

	/** Extra keying material for cipher key
	 *
	 *  Additional data used as salt or nonce if the algorithm requires it,
	 *  other algorithms ignore this field. These algorithms require this
	 *  field set:
	 *  - AES_GCM: 4 bytes of salt
	 **/
	odp_crypto_key_t cipher_key_extra;

	/** Authentication algorithm */
	odp_auth_alg_t auth_alg;

	/** Authentication key */
	odp_crypto_key_t auth_key;

} odp_ipsec_crypto_param_t;

/**
 * IPSEC tunnel parameters
 *
 * These parameters are used to build outbound tunnel headers. All values are
 * passed in CPU native byte / bit order if not specified otherwise.
 * IP addresses must be in NETWORK byte order as those are passed in with
 * pointers and copied byte-by-byte from memory to the packet.
 */
typedef struct odp_ipsec_tunnel_param_t {
	/** Tunnel type: IPv4 or IPv6 */
	odp_ipsec_tunnel_type_t type;

	/** Variant mappings for tunnel parameters */
	union {
		/** IPv4 header parameters */
		struct {
			/** IPv4 source address (NETWORK ENDIAN) */
			void *src_addr;

			/** IPv4 destination address (NETWORK ENDIAN) */
			void *dst_addr;

			/** IPv4 Differentiated Services Code Point */
			uint8_t dscp;

			/** IPv4 Don't Fragment bit */
			uint8_t df;

			/** IPv4 Time To Live */
			uint8_t ttl;
		} ipv4;

		/** IPv6 header parameters */
		struct {
			/** IPv6 source address (NETWORK ENDIAN) */
			void *src_addr;

			/** IPv6 destination address (NETWORK ENDIAN) */
			void *dst_addr;

			/** IPv6 Differentiated Services Code Point */
			uint8_t dscp;

			/** IPv6 flow label */
			uint32_t flabel;

			/** IPv6 hop limit */
			uint8_t hlimit;
		} ipv6;
	};
} odp_ipsec_tunnel_param_t;

/**
 * IPSEC SA option flags
 */
typedef struct odp_ipsec_sa_opt_t {
	/** Extended Sequence Numbers (ESN)
	  *
	  * * 1: Use extended (64 bit) sequence numbers
	  * * 0: Use normal sequence numbers
	  */
	uint32_t esn : 1;

	/** UDP encapsulation
	  *
	  * * 1: Do UDP encapsulation/decapsulation so that IPSEC packets can
	  *      traverse through NAT boxes.
	  * * 0: No UDP encapsulation
	  */
	uint32_t udp_encap : 1;

	/** Copy DSCP bits
	  *
	  * * 1: Copy IPv4 or IPv6 DSCP bits from inner IP header to
	  *      the outer IP header in encapsulation, and vice versa in
	  *      decapsulation.
	  * * 0: Use values from odp_ipsec_tunnel_param_t in encapsulation and
	  *      do not change DSCP field in decapsulation.
	  */
	uint32_t copy_dscp : 1;

	/** Copy IPv6 Flow Label
	  *
	  * * 1: Copy IPv6 flow label from inner IPv6 header to the
	  *      outer IPv6 header.
	  * * 0: Use value from odp_ipsec_tunnel_param_t
	  */
	uint32_t copy_flabel : 1;

	/** Copy IPv4 Don't Fragment bit
	  *
	  * * 1: Copy the DF bit from the inner IPv4 header to the outer
	  *      IPv4 header.
	  * * 0: Use value from odp_ipsec_tunnel_param_t
	  */
	uint32_t copy_df : 1;

	/** Decrement inner packet Time To Live (TTL) field
	  *
	  * * 1: In tunnel mode, decrement inner packet IPv4 TTL or
	  *      IPv6 Hop Limit after tunnel decapsulation, or before tunnel
	  *      encapsulation.
	  * * 0: Inner packet is not modified.
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

	/** IPSEC protocol: ESP or AH */
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
	union {
		/** Inbound specific parameters */
		struct {
			/** SA lookup mode */
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
			 *  anti-replay service.
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

		} inbound;

		/** Outbound specific parameters */
		struct {
			/** Parameters for tunnel mode */
			odp_ipsec_tunnel_param_t tunnel;

			/** Fragmentation mode */
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
 * Query IPSEC capabilities
 *
 * Outputs IPSEC capabilities on success.
 *
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_ipsec_capability(odp_ipsec_capability_t *capa);

/**
 * Query supported IPSEC cipher algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by key length, then by IV
 * length. Use this information to select key lengths, etc cipher algorithm
 * options for SA creation (odp_ipsec_crypto_param_t).
 *
 * @param      cipher       Cipher algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_ipsec_cipher_capability_t capa[], int num);

/**
 * Query supported IPSEC authentication algorithm capabilities
 *
 * Outputs all supported configuration options for the algorithm. Output is
 * sorted (from the smallest to the largest) first by digest length, then by key
 * length. Use this information to select key lengths, etc authentication
 * algorithm options for SA creation (odp_ipsec_crypto_param_t). Application
 * must ignore values for AAD length capabilities as those are not relevant for
 * IPSEC API (fixed in IPSEC RFCs).
 *
 * @param      auth         Authentication algorithm
 * @param[out] capa         Array of capability structures for output
 * @param      num          Maximum number of capability structures to output
 *
 * @return Number of capability structures for the algorithm. If this is larger
 *         than 'num', only 'num' first structures were output and application
 *         may call the function again with a larger value of 'num'.
 * @retval <0 on failure
 */
int odp_ipsec_auth_capability(odp_auth_alg_t auth,
			      odp_ipsec_auth_capability_t capa[], int num);

/**
 * Initialize IPSEC configuration options
 *
 * Initialize an odp_ipsec_config_t to its default values.
 *
 * @param[out] config  Pointer to IPSEC configuration structure
 */
void odp_ipsec_config_init(odp_ipsec_config_t *config);

/**
 * Global IPSEC configuration
 *
 * Initialize and configure IPSEC offload with global configuration options.
 * This must be called before any SAs are created. Use odp_ipsec_capability()
 * to examine which features and modes are supported. This function must be
 * called before creating the first SA with odp_ipsec_sa_create(). Calling this
 * function multiple times results in undefined behaviour.
 *
 * @param config   Pointer to IPSEC configuration structure
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_ipsec_capability(), odp_ipsec_config_init()
 */
int odp_ipsec_config(const odp_ipsec_config_t *config);

/**
 * Initialize IPSEC SA parameters
 *
 * Initialize an odp_ipsec_sa_param_t to its default values for all fields.
 *
 * @param param   Pointer to the parameter structure
 */
void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param);

/**
 * Create IPSEC SA
 *
 * Create a new IPSEC SA according to the parameters.
 *
 * @param param   IPSEC SA parameters
 *
 * @return IPSEC SA handle
 * @retval ODP_IPSEC_SA_INVALID on failure
 *
 * @see odp_ipsec_sa_param_init()
 */
odp_ipsec_sa_t odp_ipsec_sa_create(const odp_ipsec_sa_param_t *param);

/**
 * Disable IPSEC SA
 *
 * Application must use this call to disable a SA before destroying it. The call
 * marks the SA disabled, so that IPSEC implementation stops using it. For
 * example, inbound SPI lookups will not match any more. Application must
 * stop providing the SA as parameter to new IPSEC input/output operations
 * before calling disable. Packets in progress during the call may still match
 * the SA and be processed successfully.
 *
 * When in synchronous operation mode, the call will return when it's possible
 * to destroy the SA. In asynchronous mode, the same is indicated by an
 * ODP_EVENT_IPSEC_STATUS event sent to the queue specified for the SA. The
 * status event is guaranteed to be the last event for the SA, i.e. all
 * in-progress operations have completed and resulting events (including status
 * events) have been enqueued before it.
 *
 * @param sa      IPSEC SA to be disabled
 *
 * @retval 0      On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_destroy()
 */
int odp_ipsec_sa_disable(odp_ipsec_sa_t sa);

/**
 * Destroy IPSEC SA
 *
 * Destroy an unused IPSEC SA. Result is undefined if the SA is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param sa      IPSEC SA to be destroyed
 *
 * @retval 0      On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_create()
 */
int odp_ipsec_sa_destroy(odp_ipsec_sa_t sa);

/**
 * Printable format of odp_ipsec_sa_t
 *
 * @param sa      IPSEC SA handle
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa);

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

		/** All warnings bits */
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

		/** All flag bits */
		uint32_t all;
	};

} odp_ipsec_op_flag_t;

/**
 * IPSEC outbound operation options
 *
 * These may be used to override some SA level options
 */
typedef struct odp_ipsec_out_opt_t {
	/** Fragmentation mode */
	odp_ipsec_frag_mode_t mode;

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
	/** Packet output interface for inline output operation
	 *
	 *  Outbound inline IPSEC operation uses this packet IO interface to
	 *  output the packet after a successful IPSEC transformation. The pktio
	 *  must have been configured to operate in inline IPSEC mode.
	 */
	odp_pktio_t pktio;

	/** Outer headers for inline output operation
	 *
	 *  Outbound inline IPSEC operation uses this information to prepend
	 *  outer headers to the IPSEC packet before sending it out.
	 */
	struct {
		/** Points to first byte of outer headers to be copied in
		 *  front of the outgoing IPSEC packet. Implementation copies
		 *  the headers during odp_ipsec_out_inline() call. */
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
 * Inbound synchronous IPSEC operation
 *
 * This operation does inbound IPSEC processing in synchronous mode
 * (ODP_IPSEC_OP_MODE_SYNC). A successful operation returns the number of
 * packets consumed and outputs a new packet handle for each outputted packet.
 * Outputted packets contain IPSEC result metadata (odp_ipsec_packet_result_t),
 * which should be checked for transformation errors, etc. Outputted packets
 * with error status have not been transformed but the original packet is
 * returned. The operation does not modify packets that it does not consume.
 * It cannot consume all input packets if 'num_out' is smaller than 'num_in'.
 *
 * Packet context pointer and user area content are copied from input to output
 * packets. Output packets are allocated from the same pool(s) as input packets.
 *
 * When 'param.num_sa' is zero, this operation performs SA look up for each
 * packet. Otherwise, application must provide the SA(s) as part of operation
 * input parameters (odp_ipsec_in_param_t). The operation outputs used SA(s) as
 * part of per packet results (odp_ipsec_packet_result_t), or an error
 * status if a SA was not found.
 *
 * Each input packet must have a valid value for these metadata (other metadata
 * is ignored):
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 * - L4 offset: When udp_encap is enabled, offset to the first byte of the
 *              encapsulating UDP header
 *
 * Additionally, implementation checks input IP packet length (odp_packet_len()
 * minus odp_packet_l3_offset()) against protocol headers and reports an error
 * (status.error.proto) if packet data length is less than protocol headers
 * indicate.
 *
 * Packets are processed in the input order. Packet order is maintained from
 * input 'pkt' array to output 'pkt' array. Packet order is not guaranteed
 * between calling threads.
 *
 * Input packets must not be IP fragments.
 *
 * The operation does packet transformation according to IPSEC standards (see
 * e.g. RFC 4302 and 4303). Resulting packets are well formed, reconstructed
 * original IP packets, with IPSEC headers removed and valid header field values
 * restored. The amount and content of packet data before the IP header is
 * undefined.
 *
 * Each successfully transformed packet has a valid value for these metadata
 * regardless of the inner packet parse configuration
 * (odp_ipsec_inbound_config_t):
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 * - pktio:     For inline IPSEC processed packets, original packet input
 *              interface
 *
 * Other metadata for parse results and error checks depend on configuration
 * (selected parse and error check levels).
 *
 * @param          pkt_in   Packets to be processed
 * @param          num_in   Number of packets to be processed
 * @param[out]     pkt_out  Packet handle array for resulting packets
 * @param[in, out] num_out  Number of resulting packets. Application sets this
 *                          to 'pkt_out' array size. A successful operation sets
 *                          this to the number of outputted packets
 *                          (1 ... num_out).
 * @param          param    Inbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num_in)
 * @retval <0     On failure
 *
 * @see odp_packet_user_ptr(), odp_packet_user_area(), odp_packet_l3_offset(),
 * odp_packet_l4_offset()
 */
int odp_ipsec_in(const odp_packet_t pkt_in[], int num_in,
		 odp_packet_t pkt_out[], int *num_out,
		 const odp_ipsec_in_param_t *param);

/**
 * Outbound synchronous IPSEC operation
 *
 * This operation does outbound IPSEC processing in synchronous mode
 * (ODP_IPSEC_OP_MODE_SYNC). A successful operation returns the number of
 * packets consumed and outputs a new packet handle for each outputted packet.
 * Outputted packets contain IPSEC result metadata (odp_ipsec_packet_result_t),
 * which should be checked for transformation errors, etc. Outputted packets
 * with error status have not been transformed but the original packet is
 * returned. The operation does not modify packets that it does not consume.
 * It cannot consume all input packets if 'num_out' is smaller than 'num_in'.
 *
 * Packet context pointer and user area content are copied from input to output
 * packets. Output packets are allocated from the same pool(s) as input packets.
 *
 * When outbound IP fragmentation offload is enabled, the number of outputted
 * packets may be greater than the number of input packets.
 *
 * Each input packet must have a valid value for these metadata (other metadata
 * is ignored):
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 * - L4 offset: Offset to the L4 header if L4 checksum offload is requested
 *
 * Additionally, input IP packet length (odp_packet_len() minus
 * odp_packet_l3_offset()) must match values in protocol headers. Otherwise
 * results are undefined.
 *
 * Packets are processed in the input order. Packet order is maintained from
 * input 'pkt' array to output 'pkt' array. Packet order is not guaranteed
 * between calling threads.
 *
 * The operation does packet transformation according to IPSEC standards (see
 * e.g. RFC 4302 and 4303). Resulting packets are well formed IP packets
 * with IPSEC, etc headers constructed according to the standards. The amount
 * and content of packet data before the IP header is undefined.
 *
 * Each successfully transformed packet has a valid value for these metadata:
 * - L3 offset: Offset to the first byte of the (outmost) IP header
 *
 * @param          pkt_in   Packets to be processed
 * @param          num_in   Number of packets to be processed
 * @param[out]     pkt_out  Packet handle array for resulting packets
 * @param[in, out] num_out  Number of resulting packets. Application sets this
 *                          to 'pkt_out' array size. A successful operation sets
 *                          this to the number of outputted packets
 *                          (1 ... num_out).
 * @param          param    Outbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num_in)
 * @retval <0     On failure
 *
 * @see odp_packet_user_ptr(), odp_packet_user_area(), odp_packet_l3_offset()
 */
int odp_ipsec_out(const odp_packet_t pkt_in[], int num_in,
		  odp_packet_t pkt_out[], int *num_out,
		  const odp_ipsec_out_param_t *param);

/**
 * Inbound asynchronous IPSEC operation
 *
 * This operation does inbound IPSEC processing in asynchronous mode. It
 * processes packets otherwise identically to odp_ipsec_in(), but outputs
 * resulting packets as ODP_EVENT_PACKET events (with ODP_EVENT_PACKET_IPSEC
 * subtype). The following ordering considerations apply to the events.
 *
 * Asynchronous mode maintains packet order per SA when application calls the
 * operation within an ordered or atomic scheduler context of the same queue.
 * Resulting events for the same SA are enqueued in order. Packet order per SA
 * at a destination queue is the same as if application would have enqueued
 * packets there with odp_queue_enq_multi().
 *
 * Packet order is also maintained when application otherwise guarantees
 * (e.g. using locks) that the operation is not called simultaneously from
 * multiple threads for the same SA(s).
 *
 * Logically, packet processing (e.g. sequence number check) happens in the
 * output order as defined above.
 *
 * The function may be used also in inline processing mode, e.g. for IPSEC
 * packets for which inline processing is not possible. Packets for the same SA
 * may be processed simultaneously in both modes (initiated by this function
 * and inline operation).
 *
 * @param          pkt      Packets to be processed
 * @param          num      Number of packets to be processed
 * @param          param    Inbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_in(), odp_ipsec_result()
 */
int odp_ipsec_in_enq(const odp_packet_t pkt[], int num,
		     const odp_ipsec_in_param_t *param);

/**
 * Outbound asynchronous IPSEC operation
 *
 * This operation does outbound IPSEC processing in asynchronous mode. It
 * processes packets otherwise identically to odp_ipsec_out(), but outputs
 * resulting packets as ODP_EVENT_PACKET events (with ODP_EVENT_PACKET_IPSEC
 * subtype). The following ordering considerations apply to the events.
 *
 * Asynchronous mode maintains packet order per SA when application calls the
 * operation within an ordered or atomic scheduler context of the same queue.
 * Resulting events for the same SA are enqueued in order. Packet order per SA
 * at a destination queue is the same as if application would have enqueued
 * packets there with odp_queue_enq_multi().
 *
 * Packet order is also maintained when application otherwise guarantees
 * (e.g. using locks) that the operation is not called simultaneously from
 * multiple threads for the same SA(s).
 *
 * Logically, packet processing (e.g. sequence number assignment) happens in the
 * output order as defined above.
 *
 * The function may be used also in inline processing mode, e.g. for IPSEC
 * packets for which inline processing is not possible.
 *
 * @param          pkt      Packets to be processed
 * @param          num      Number of packets to be processed
 * @param          param    Outbound operation parameters
 *
 * @return Number of input packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_out(), odp_ipsec_result()
 */
int odp_ipsec_out_enq(const odp_packet_t pkt[], int num,
		      const odp_ipsec_out_param_t *param);

/**
 * Outbound inline IPSEC operation
 *
 * This operation does outbound inline IPSEC processing for the packets. It's
 * otherwise identical to odp_ipsec_out_enq(), but outputs all successfully
 * transformed packets to the specified output interface, instead of generating
 * events for those.
 *
 * Inline operation parameters are defined per packet. The array of parameters
 * must have 'num' elements and is pointed to by 'inline_param'.
 *
 * @param          pkt           Packets to be processed
 * @param          num           Number of packets to be processed
 * @param          param         Outbound operation parameters
 * @param          inline_param  Outbound inline operation specific parameters
 *
 * @return Number of packets consumed (0 ... num)
 * @retval <0     On failure
 *
 * @see odp_ipsec_out_enq()
 */
int odp_ipsec_out_inline(const odp_packet_t pkt[], int num,
			 const odp_ipsec_out_param_t *param,
			 const odp_ipsec_out_inline_param_t *inline_param);

/**
 * Convert IPSEC processed packet event to packet handle
 *
 * Get packet handle to an IPSEC processed packet event. Event subtype must be
 * ODP_EVENT_IPSEC_PACKET. IPSEC operation results can be examined with
 * odp_ipsec_result().
 *
 * @param ev       Event handle
 *
 * @return Packet handle
 *
 * @see odp_event_subtype(), odp_ipsec_result()
 */
odp_packet_t odp_ipsec_packet_from_event(odp_event_t ev);

/**
 * Convert IPSEC processed packet handle to event
 *
 * The packet handle must be an output of an IPSEC operation.
 *
 * @param pkt      Packet handle from IPSEC operation
 *
 * @return Event handle
 */
odp_event_t odp_ipsec_packet_to_event(odp_packet_t pkt);

/**
 * Get IPSEC operation results from an IPSEC processed packet
 *
 * Successful IPSEC operations of all types (SYNC, ASYNC and INLINE) produce
 * packets which contain IPSEC result metadata. This function copies the
 * operation results from an IPSEC processed packet. Event subtype of this kind
 * of packet is ODP_EVENT_PACKET_IPSEC. Results are undefined if a non-IPSEC
 * processed packet is passed as input.
 *
 * Some packet API operations output a new packet handle
 * (e.g. odp_packet_concat()). IPSEC metadata remain valid as long as the packet
 * handle is not changed from the original (output of e.g. odp_ipsec_in() or
 * odp_ipsec_packet_from_event() call) IPSEC processed packet handle.
 *
 * @param[out]    result  Pointer to operation result for output
 * @param         packet  An IPSEC processed packet (ODP_EVENT_PACKET_IPSEC)
 *
 * @retval  0     On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_in(), odp_ipsec_in_enq(), odp_ipsec_out(),
 *      odp_ipsec_out_enq(), odp_ipsec_packet_from_event()
 */
int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t packet);

/**
 * Get IPSEC status information from an ODP_EVENT_IPSEC_STATUS event
 *
 * Copies IPSEC status information from an event. The event must be of
 * type ODP_EVENT_IPSEC_STATUS.
 *
 * @param[out]    status  Pointer to status information structure for output.
 * @param         event   An ODP_EVENT_IPSEC_STATUS event
 *
 * @retval  0     On success
 * @retval <0     On failure
 *
 * @see odp_ipsec_sa_disable()
 */
int odp_ipsec_status(odp_ipsec_status_t *status, odp_event_t event);

/**
 * Update MTU for outbound IP fragmentation
 *
 * When IP fragmentation offload is enabled, the SA is created with an MTU.
 * This call may be used to update MTU at any time. MTU updates are not
 * expected to happen very frequently.
 *
 * @param sa      IPSEC SA to be updated
 * @param mtu     The new MTU value
 *
 * @retval 0      On success
 * @retval <0     On failure
 */
int odp_ipsec_sa_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu);

/**
 * Get user defined SA context pointer
 *
 * @param sa      IPSEC SA handle
 *
 * @return User defined SA context pointer value
 * @retval NULL   On failure
 */
void *odp_ipsec_sa_context(odp_ipsec_sa_t sa);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
