/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_API_SPEC_CLASSIFICATION_H_
#define ODP_API_SPEC_CLASSIFICATION_H_
#include <odp/visibility_begin.h>

#include <odp/api/packet_io_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>
#include <odp/api/threshold.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_classification ODP CLASSIFICATION
 *  Packet input classification.
 *  @{
 */

/**
 * @typedef odp_pmr_t
 * Packet matching rule handle
 */

/**
 * @def ODP_PMR_INVALID
 * Invalid packet matching rule handle
 */

/**
 * @typedef odp_cos_t
 * Class of service handle
 */

/**
 * @def ODP_COS_INVALID
 * Invalid class of service handle
 */

/**
 * @def ODP_COS_NAME_LEN
 * Maximum class of service name length, including the null character
 */

/**
 * Packet Matching Rule terms
 *
 * This enumeration selects the protocol field that is matched against PMR
 * value/mask or value range. Protocol field values and masks are passed in big
 * endian (network endian) format. However, ODP_PMR_LEN value and range are
 * passed in CPU native endian (uint32_t words), as the term does not represent
 * a protocol field.
 *
 * PMR value/mask data size is term specific. This size must be set into val_sz
 * field of odp_pmr_param_t. There is no alignment requirement for PMR
 * value/mask data.
 */
typedef enum {
	/** Total length of received packet. Exceptionally, value and mask are
	  * uint32_t (val_sz = 4) in CPU endian. */
	ODP_PMR_LEN,

	/** Initial (outer) Ethertype only (val_sz = 2)
	 *
	 *  PMR matches Ethertype field when packet does not have VLAN headers. When there are
	 *  VLAN headers, it matches Tag protocol identifier (TPID) field of the first VLAN header.
	 *  I.e. it matches a field in the same offset from the start of the packet in both cases.
	 */
	ODP_PMR_ETHTYPE_0,

	/** Ethertype of most inner VLAN tag (val_sz = 2) */
	ODP_PMR_ETHTYPE_X,

	/** First (outer) VLAN ID (val_sz = 2)
	 *
	 *  VLAN ID value and mask are stored into 12 least significant bits of a 16-bit word.
	 *  The word is passed in big endian format.
	 */
	ODP_PMR_VLAN_ID_0,

	/** Last (most inner) VLAN ID (val_sz = 2)
	 *
	 *  VLAN ID value and mask are stored into 12 least significant bits of a 16-bit word.
	 *  The word is passed in big endian format.
	 */
	ODP_PMR_VLAN_ID_X,

	/** PCP bits in the first (outer) VLAN header (val_sz = 1)
	 *
	 *  Priority Code Point (PCP) value is stored into three least significant bits of
	 *  the octet pointed by odp_pmr_param_t::value. The same applies for odp_pmr_param_t::mask.
	 */
	ODP_PMR_VLAN_PCP_0,

	/** Destination MAC address (val_sz = 6) */
	ODP_PMR_DMAC,

	/** IPv4 Protocol or IPv6 Next Header (val_sz = 1) */
	ODP_PMR_IPPROTO,

	/** Differentiated Services Code Point (DSCP) bits in IPv4 or IPv6 header (val_sz = 1)
	 *
	 *  DSCP value is stored into six least significant bits of the octet pointed by
	 *  odp_pmr_param_t::value. The same applies for odp_pmr_param_t::mask.
	 */
	ODP_PMR_IP_DSCP,

	/** Destination UDP port (val_sz = 2) */
	ODP_PMR_UDP_DPORT,

	/** Destination TCP port (val_sz = 2) */
	ODP_PMR_TCP_DPORT,

	/** Source UDP port (val_sz = 2) */
	ODP_PMR_UDP_SPORT,

	/** Source TCP port (val_sz = 2) */
	ODP_PMR_TCP_SPORT,

	/** Source IPv4 address (val_sz = 4) */
	ODP_PMR_SIP_ADDR,

	/** Destination IPv4 address (val_sz = 4) */
	ODP_PMR_DIP_ADDR,

	/** Source IPv6 address (val_sz = 16) */
	ODP_PMR_SIP6_ADDR,

	/** Destination IPv6 address (val_sz = 16) */
	ODP_PMR_DIP6_ADDR,

	/** IPsec session identifier (val_sz = 4)*/
	ODP_PMR_IPSEC_SPI,

	/** NVGRE/VXLAN network identifier (val_sz = 4) */
	ODP_PMR_LD_VNI,

	/**
	 * Custom frame match rule
	 *
	 * PMR offset is counted from the start of the packet. The match is
	 * defined by the offset, the expected value, and its size. Custom frame
	 * rules must be applied before any other PMR.
	 */
	ODP_PMR_CUSTOM_FRAME,

	/**
	 * Custom layer 3 match rule
	 *
	 * PMR offset is counted from the start of layer 3 in the packet.
	 * The match is defined by the offset, the expected value, and its size.
	 * Custom L3 rules may be combined with other PMRs.
	 */
	ODP_PMR_CUSTOM_L3,

	/** IGMP Group address (val_sz = 4), implies IPPROTO=2 */
	ODP_PMR_IGMP_GRP_ADDR,

	/** ICMP identifier (val_sz = 2), implies IPPROTO=1 and ICMP_TYPE=0 or ICMP_TYPE=8 */
	ODP_PMR_ICMP_ID,

	/** ICMP type (val_sz = 1), implies IPPROTO=1 */
	ODP_PMR_ICMP_TYPE,

	/** ICMP code (val_sz = 1), implies IPPROTO=1 */
	ODP_PMR_ICMP_CODE,

	/** Source SCTP port (val_sz = 2), implies IPPROTO=132 */
	ODP_PMR_SCTP_SPORT,

	/** Destination SCTP port (val_sz = 2), implies IPPROTO=132 */
	ODP_PMR_SCTP_DPORT,

	/** GTPv1 tunnel endpoint identifier (val_sz = 4)
	 *
	 * Matches if and only if IP protocol is UDP, UDP destination port
	 * is 2152 and the UDP payload interpreted as GTP header has GTP
	 * version 1 and TEID as specified.
	 */
	ODP_PMR_GTPV1_TEID,

	/** Inner header may repeat above values with this offset */
	ODP_PMR_INNER_HDR_OFF = 32

} odp_cls_pmr_term_t;

/**
 * Supported PMR term values
 *
 * Supported Packet Matching Rule term values in a bit field structure.
 */
typedef union odp_cls_pmr_terms_t {
	/** Packet Matching Rule term fields */
	struct {
		/** Total length of received packet */
		uint64_t	len:1;
		/** Initial (outer) Ethertype only */
		uint64_t	ethtype_0:1;
		/** Ethertype of most inner VLAN tag */
		uint64_t	ethtype_x:1;
		/** First VLAN ID (outer) */
		uint64_t	vlan_id_0:1;
		/** Last VLAN ID (inner) */
		uint64_t	vlan_id_x:1;
		/** PCP in the first VLAN header (#ODP_PMR_VLAN_PCP_0) */
		uint64_t	vlan_pcp_0:1;
		/** destination MAC address */
		uint64_t	dmac:1;
		/** IP Protocol or IPv6 Next Header */
		uint64_t	ip_proto:1;
		/** DSCP in IP header (#ODP_PMR_IP_DSCP) */
		uint64_t	ip_dscp:1;
		/** Destination UDP port, implies IPPROTO=17 */
		uint64_t	udp_dport:1;
		/** Destination TCP port implies IPPROTO=6 */
		uint64_t	tcp_dport:1;
		/** Source UDP Port */
		uint64_t	udp_sport:1;
		/** Source TCP port */
		uint64_t	tcp_sport:1;
		/** Source IP address */
		uint64_t	sip_addr:1;
		/** Destination IP address */
		uint64_t	dip_addr:1;
		/** Source IP address */
		uint64_t	sip6_addr:1;
		/** Destination IP address */
		uint64_t	dip6_addr:1;
		/** IPsec session identifier */
		uint64_t	ipsec_spi:1;
		/** NVGRE/VXLAN network identifier */
		uint64_t	ld_vni:1;
		/** Custom frame match rule. PMR offset is counted from
		 *  the start of the packet. */
		uint64_t        custom_frame:1;
		/** Custom layer 3 match rule. PMR offset is counted from
		 *  the start of layer 3 in the packet. */
		uint64_t        custom_l3:1;
		/** IGMP Group address, implies IPPROTO=2 */
		uint64_t	igmp_grp_addr:1;
		/** ICMP identifier, implies IPPROTO=1 and ICMP_TYPE=0 or ICMP_TYPE=8 */
		uint64_t	icmp_id:1;
		/** ICMP type, implies IPPROTO=1 */
		uint64_t	icmp_type:1;
		/** ICMP code, implies IPPROTO=1 */
		uint64_t	icmp_code:1;
		/** Source SCTP port, implies IPPROTO=132 */
		uint64_t	sctp_sport:1;
		/** Destination SCTP port, implies IPPROTO=132 */
		uint64_t	sctp_dport:1;
		/** GTPv1 tunnel endpoint identifier */
		uint64_t	gtpv1_teid:1;
	} bit;

	/** All bits of the bit field structure */
	uint64_t all_bits;

} odp_cls_pmr_terms_t;

/**
 * Packet Matching Rule parameter structure
 *
 * Match value/mask size and endianness are defined in PMR term documentation
 * (see odp_cls_pmr_term_t). Most values and masks are passed in big
 * endian format without data alignment requirement. ODP_PMR_LEN is
 * an exception to this (uint32_t in CPU endian).
 */
typedef struct odp_pmr_param_t {
	/** Packet Matching Rule term */
	odp_cls_pmr_term_t  term;

	/** True if the value is range and false if match. Default is false. */
	odp_bool_t range_term;

	/** Variant mappings for types of matches */
	union {
		/** Parameters for single-valued matches */
		struct {
			/** Points to the value to be matched. Value size and
			 *  endianness are defined by the term used. Values of
			 *  protocol fields are defined in big endian format.
			 */
			const void *value;

			/** Mask of the bits to be matched. The same size and
			 *  endianness is used than with the value. */
			const void *mask;
		} match;

		/** Parameter for range value matches */
		struct {
			/** Start value of the range */
			const void *val_start;

			/** End value of the range */
			const void *val_end;
		} range;
	};

	/** Size of the value to be matched */
	uint32_t val_sz;

	/** Offset to the value
	 *
	 * Byte offset to the value to be matched in a packet. PMR term defines
	 * starting point for the offset. Used only with custom PMR terms,
	 * ignored with other terms.
	 */
	uint32_t offset;

} odp_pmr_param_t;

/**
 * Packet Matching Rule creation options
 */
typedef struct odp_pmr_create_opt_t {
	/** PMR terms
	 *
	 *  Array of odp_pmr_param_t entries, one entry per term desired.
	 *  Use odp_cls_pmr_param_init() to initialize parameters into their default values.
	 */
	odp_pmr_param_t *terms;

	/** Number of terms in the match rule. */
	int num_terms;

	/** Classification mark value
	 *
	 * Value to be set in the CLS mark of a packet when the packet matches this
	 * Packet Matching Rule. The default value is zero. The maximum value is indicated in
	 * odp_cls_capability_t::max_mark capability.
	 */
	uint64_t mark;

	/** Rule priority
	 *
	 *  When multiple PMRs match a packet, a matching rule with the
	 *  highest priority is selected. If there are multiple such rules,
	 *  then it is implementation specific which one is selected.
	 *
	 *  Larger priority value corresponds to higher priority. The value
	 *  must not be larger than odp_cls_capability_t::max_pmr_priority.
	 *  The default value is 0.
	 */
	uint32_t priority;

} odp_pmr_create_opt_t;

/** Random Early Detection (RED)
 * Random Early Detection is enabled to initiate a drop probability for the
 * incoming packet when the packets in the queue/pool cross the specified
 * threshold values. RED is enabled when 'red_enable' boolean is true and
 * the resource usage is equal to or greater than the minimum threshold value.
 * Resource usage could be defined either as the percentage of pool being full
 * or the number of packets/bytes occupied in the queue depending on the
 * platform capabilities.
 *
 * When RED is enabled for a particular flow then further incoming packets are
 * assigned a drop probability based on the size of the pool/queue.
 *
 * Drop probability is configured as follows
 * * Drop probability is 100%, when resource usage >= threshold.max
 * * Drop probability is 0%, when resource usage <= threshold.min
 * * Drop probability is between 0...100 % when resource usage is between
 *	threshold.min and threshold.max
 *
 * RED is logically configured in the CoS and could be implemented in either
 * pool or queue linked to the CoS depending on platform capabilities.
 * Application should make sure not to link multiple CoS with different RED or
 * BP configuration to the same queue or pool.
 */
typedef struct odp_red_param_t {
	/** A boolean to enable RED
	 * When true, RED is enabled and configured with RED parameters.
	 * Otherwise, RED parameters are ignored. Default value is false.
	 */
	odp_bool_t enable;

	/** Threshold parameters for RED
	 * RED is enabled when the resource usage is equal to or greater than
	 * the minimum threshold value and is disabled otherwise
	 */
	odp_threshold_t threshold;

} odp_red_param_t;

/** Back pressure (BP)
 *
 * When back pressure is enabled, HW can send back pressure to the remote peer
 * indicating resource shortage. Depending on the implementation, back pressure
 * can be asserted when the fill level of the destination queue of a CoS
 * exceeds the configured threshold or when the utilization of the packet pool
 * associated with a CoS exceeds the configured threshold.
 *
 * If multiple CoSes configure back pressure for the same pktio, pool/queue
 * and pfc level, then back pressure is sent as long as any of the CoSes
 * assert back pressure. There does not have to be packets flowing through
 * a CoS node for the CoS to assert back pressure, because packets may be
 * directed to the same queue/pool by some other CoS node (which might not
 * even have backpressure configured), some other ODP component or the ODP
 * application.
 *
 * Conceptually, a configured CoS hierarchy determines unique global back
 * pressure threshold for each (pktio, queue/pool, pfc_level)-tuple. The
 * back pressure configuration in a CoS affects the global thresholds that
 * have the same queue/pool as configured in the Cos, the same pfc_level
 * (if PFC is enabled) and a pktio that is a connected to the CoS. One
 * CoS can affect multiple global thresholds and one global threshold can
 * be affected by multiple CoSes (in which case the minimum of the
 * configured thresholds is used).
 */
typedef struct odp_bp_param_t {
	/** A boolean to enable Back pressure
	 * When true, back pressure is enabled and configured with the BP
	 * parameters. Otherwise BP parameters are ignored. Default value
	 * is false.
	 */
	odp_bool_t enable;

	/** Threshold value for back pressure.
	 * BP is enabled when the resource usage is equal to or greater than the
	 * max backpressure threshold. Min threshold parameters are ignored for
	 * BP configuration.
	 * @see odp_red_param_t for 'resource usage' documentation.
	 */
	odp_threshold_t threshold;

	/**
	 * PFC priority level
	 *
	 * When enabled (#ODP_PKTIO_LINK_PFC_ON), PFC frames are generated when the above
	 * threshold is exceeded. The generated frames request the receiver to temporary halt
	 * transmission of traffic on this priority level (0 .. 7).
	 */
	uint8_t pfc_level;

} odp_bp_param_t;

/**
 * Classifier CoS specific statistics counters
 *
 * Counters are incremented per packet classified to the CoS. In a CoS chain,
 * counters are incremented in every CoS for which counters are enabled.
 */
typedef struct odp_cls_cos_stats_t {
	/** Number of octets in classified packets. In case of Ethernet, packet
	 * size includes MAC header. */
	uint64_t octets;

	/** Number of classified packets, including packets dropped due to drop
	 * action. */
	uint64_t packets;

	/** Number of discarded packets due to other reasons than packet
	 * errors or drop action. */
	uint64_t discards;

	/** Number of packets with errors. */
	uint64_t errors;

} odp_cls_cos_stats_t;

/**
 * Classifier queue specific statistics counters
 *
 * Counters are incremented per packet destined to the queue per originating
 * CoS. Note that a single queue can be a destination for multiple CoS's.
 */
typedef struct odp_cls_queue_stats_t {
	/** Number of octets in successfully delivered packets. In case of
	 *  Ethernet, packet size includes MAC header. */
	uint64_t octets;

	/** Number of successfully delivered packets. */
	uint64_t packets;

	/** Number of discarded packets due to other reasons (e.g. RED) than
	 *  errors. */
	uint64_t discards;

	/** Number of packets with errors. Depending on packet input
	 *  configuration, packets with errors may be dropped or not. */
	uint64_t errors;

} odp_cls_queue_stats_t;

/**
 * Classifier statistics capabilities
 */
typedef struct odp_cls_stats_capability_t {
	/** CoS level capabilities */
	struct {
		/** Supported counters */
		union {
			/** Statistics counters in a bit field structure */
			struct {
				/** See odp_cls_cos_stats_t::octets */
				uint64_t octets          : 1;

				/** See odp_cls_cos_stats_t::packets */
				uint64_t packets         : 1;

				/** See odp_cls_cos_stats_t::discards */
				uint64_t discards        : 1;

				/** See odp_cls_cos_stats_t::errors */
				uint64_t errors          : 1;

			} counter;

			/** All bits of the bit field structure
			 *
			 *  This field can be used to set/clear all flags, or
			 *  for bitwise operations over the entire structure. */
			uint64_t all_counters;
		};
	} cos;

	/** Queue level capabilities */
	struct {
		/** Supported counters */
		union {
			/** Statistics counters in a bit field structure */
			struct {
				/** See odp_cls_queue_stats_t::octets */
				uint64_t octets          : 1;

				/** See odp_cls_queue_stats_t::packets */
				uint64_t packets         : 1;

				/** See odp_cls_queue_stats_t::discards */
				uint64_t discards        : 1;

				/** See odp_cls_queue_stats_t::errors */
				uint64_t errors          : 1;

			} counter;

			/** All bits of the bit field structure
			 *
			 *  This field can be used to set/clear all flags, or
			 *  for bitwise operations over the entire structure. */
			uint64_t all_counters;
		};
	} queue;

} odp_cls_stats_capability_t;

/** Event aggregator related capabilities */
typedef struct odp_cls_aggr_capability_t {
	/** Supported enqueuing profile types in addition to ODP_AEP_TYPE_NONE,
	 *  which is always supported. See odp_aggr_enq_profile_t. */
	struct {
		/** IPv4 fragment profile (ODP_AEP_TYPE_IPV4_FRAG) */
		uint64_t ipv4_frag : 1;

		/** IPv6 fragment profile (ODP_AEP_TYPE_IPV6_FRAG) */
		uint64_t ipv6_frag : 1;

		/** Custom profile (ODP_AEP_TYPE_CUSTOM) */
		uint64_t custom : 1;

	} enq_profile_type;

} odp_cls_aggr_capability_t;

/**
 * Classification capabilities
 * This capability structure defines system level classification capability
 */
typedef struct odp_cls_capability_t {
	/** PMR terms supported by the classifier
	 *
	 * A bit mask of one bit for each of odp_pmr_term_t. */
	odp_cls_pmr_terms_t supported_terms;

	/** Maximum number of single-term PMRs
	 *
	 * Depending on the implementation, using several/composite terms for a
	 * single PMR may end up incurring more than one PMR element from this
	 * total capacity. */
	uint32_t max_pmr;

	/** Maximum number of PMRs per CoS */
	uint32_t max_pmr_per_cos;

	/** Maximum number of terms per composite PMR */
	uint32_t max_terms_per_pmr;

	/** Maximum priority value of a PMR */
	uint32_t max_pmr_priority;

	/** Maximum number of CoS supported */
	uint32_t max_cos;

	/** Maximum number of concurrent CoS stats
	 *
	 * Maximum number of CoSes that can have statistics enabled at the same
	 * time. If this value is zero, then CoS level statistics are not
	 * supported. */
	uint32_t max_cos_stats;

	/** Maximum number of queues supported per CoS
	 *
	 * If the value is 1, then hashing is not supported. */
	uint32_t max_hash_queues;

	/** Protocol header combination supported for Hashing */
	odp_pktin_hash_proto_t hash_protocols;

	/** A Boolean to denote support of PMR range */
	odp_bool_t pmr_range_supported;

	/** Support for Random Early Detection */
	odp_support_t random_early_detection;

	/** Supported threshold type for RED */
	odp_threshold_types_t threshold_red;

	/** Support for Back Pressure to the remote peer */
	odp_support_t back_pressure;

	/** Supported threshold type for BP */
	odp_threshold_types_t threshold_bp;

	/** Maximum value of odp_pmr_create_opt_t::mark */
	uint64_t max_mark;

	/** Statistics counters capabilities */
	odp_cls_stats_capability_t stats;

	/** Event aggregator related capabilities */
	odp_cls_aggr_capability_t aggr;

} odp_cls_capability_t;

/**
 * Enumeration of actions for CoS.
 */
typedef enum {
	/**
	 * Enqueue packet
	 *
	 * Packets that arrive in the CoS are enqueued to a destination queue.
	 */
	ODP_COS_ACTION_ENQUEUE,

	/**
	 * Drop packet
	 *
	 * Packets that arrive in the CoS are dropped. Packets are freed into
	 * their originating pool.
	 */
	ODP_COS_ACTION_DROP,

} odp_cos_action_t;

/**
 * Class of service parameters
 * Used to communicate class of service creation options
 */
typedef struct odp_cls_cos_param {
	/** Action to take. When action is ODP_COS_ACTION_DROP, all the other
	 * parameters are ignored. If action is ODP_COS_ACTION_ENQUEUE, then
	 * queue must be set, or num_queue must be greater than one.
	 *
	 * The final match in the CoS chain defines the action for a packet.
	 * I.e. packet is dropped only when the CoS of the last matching rule
	 * has drop action. Actions in the previous CoSes in the chain are
	 * ignored.
	 *
	 * Default is ODP_COS_ACTION_ENQUEUE.
	 */
	odp_cos_action_t action;

	/** Enable statistics. If true, counters are incremented when packets
	 * are classified to the CoS. Default is false.
	 *
	 * @see odp_cls_cos_stats()
	 */
	odp_bool_t stats_enable;

	/** Number of queues to be linked to this CoS.
	 * If the number is greater than 1 then hashing is enabled.
	 * If number is equal to 1 then hashing is disabled.
	 * When hashing is enabled the queues are created by the implementation
	 * and application need not configure any queue to the class of service.
	 * When hashing is disabled application has to configure the queue to
	 * the class of service.
	 * Depending on the implementation this number might be rounded-off to
	 * nearest supported value (e.g power of 2)
	 *
	 * Default value is 1.
	 */
	uint32_t num_queue;

	/** Variant mapping for queue hash configuration */
	union {
		/** Mapping used when num_queue = 1, hashing is disabled in
		 * this case and application has to configure this queue and
		 * packets are delivered to this queue */
		odp_queue_t queue;

		/** Mapping used when num_queue > 1, hashing is enabled in
		 * this case and queues are created by the implementation */
		struct {
			/** Queue parameters */
			odp_queue_param_t queue_param;

			/** Protocol header fields which are included in
			 * packet input hash calculation */
			odp_pktin_hash_proto_t hash_proto;
		};
	};
	/** Pool associated with CoS
	 *
	 * May be set to ODP_POOL_INVALID, in which case the default pool of
	 * the originating packet input is used (see odp_pktio_open()). If
	 * there is no originating packet input (e.g. with lookaside IPsec),
	 * then this parameter must be set to a valid pool.
	 *
	 * Default is ODP_POOL_INVALID.
	 */
	odp_pool_t pool;

	/** Random Early Detection configuration */
	odp_red_param_t red;

	/** Back Pressure configuration */
	odp_bp_param_t bp;

	/** Packet input vector configuration
	 *
	 * Generating vectors of packets can be enabled either through this
	 * configuration or by using event aggregators as destination queue(s).
	 * Both options cannot be enabled simultaneously in the same ODP
	 * application.
	 */
	odp_pktin_vector_config_t vector;

	/** Event aggregator enqueuing profile
	 *
	 * This parameter has an effect only when a packet is enqueued to
	 * an aggregator queue by this CoS.
	 *
	 * If the profile is not one of the supported types indicated in
	 * odp_cls_capability_t::aggr.enq_profile_type, or if the profile
	 * type is supported but the profile cannot be supported in this CoS
	 * instance (e.g. due to resource constraints), CoS creation will fail.
	 */
	odp_aggr_enq_profile_t aggr_enq_profile;

} odp_cls_cos_param_t;

/**
 * Initialize class of service parameters
 *
 * Initialize an odp_cls_cos_param_t to its default value for all fields
 *
 * @param param        Address of the odp_cls_cos_param_t to be initialized
 */
void odp_cls_cos_param_init(odp_cls_cos_param_t *param);

/**
 * Query classification capabilities
 *
 * Outputs classification capabilities on success.
 *
 * @param[out] capability  Pointer to classification capability structure.
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cls_capability(odp_cls_capability_t *capability);

/**
 * Create a class-of-service
 *
 * Depending on the action parameter, packets to the CoS are either enqueued to
 * a destination queue, or dropped.
 *
 * The use of class-of-service name is optional. Unique names are not required.
 * Use odp_cls_cos_param_init() to initialize parameters into their default
 * values.
 *
 * @param name         Name of the class-of-service or NULL. Maximum string
 *                     length is ODP_COS_NAME_LEN, including the null character.
 * @param param        Class-of-service parameters
 *
 * @retval Class-of-service handle
 * @retval ODP_COS_INVALID on failure.
 */
odp_cos_t odp_cls_cos_create(const char *name,
			     const odp_cls_cos_param_t *param);

/**
 * Create multiple class-of-services
 *
 * Otherwise like odp_cls_cos_create(), but creates multiple CoSes with a
 * single call. The output CoS handles are written in the same order as input
 * parameters. A single odp_cls_cos_create_multi() call is equivalent to calling
 * odp_cls_cos_create() 'num' times in row.
 *
 * Each parameter array must contain 'num' elements with the exception that
 * 'name' array may also be NULL.
 *
 * @param      name     Array of CoS name pointers or NULL. NULL is also valid
 *                      CoS name pointer value.
 * @param      param    Array of CoS parameters
 * @param[out] cos      Array of CoS handles for output
 * @param      num      Number of CoSes to create
 *
 * @return Number of CoSes actually created (0 ... num)
 * @retval <0 on failure
 */
int odp_cls_cos_create_multi(const char *name[],
			     const odp_cls_cos_param_t param[],
			     odp_cos_t cos[], int num);

/**
 * Queue hash result
 * Returns the queue within a CoS in which a particular packet will be enqueued
 * based on the packet parameters and hash protocol field configured with the
 * class of service.
 *
 * @param cos          CoS handle
 * @param packet       Packet handle
 *
 * @retval Returns the queue handle on which this packet will be enqueued.
 * @retval ODP_QUEUE_INVALID for error case
 *
 * @note The packet has to be updated with valid header pointers L2, L3 and L4.
 */
odp_queue_t odp_cls_hash_result(odp_cos_t cos, odp_packet_t packet);

/**
 * Discard a class-of-service along with all its associated resources
 *
 * Before destroying a CoS, all the PMRs referring to the CoS (as a source or
 * destination CoS) must be destroyed first. Also, the CoS must not be in use
 * as the default CoS in any pktio (see odp_pktio_default_cos_set()) or as the
 * destination CoS of any IPsec SA.
 *
 * @param cos          CoS handle
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cos_destroy(odp_cos_t cos);

/**
 * Destroy multiple class-of-services
 *
 * Otherwise like odp_cos_destroy(), but destroys multiple CoSes with a single
 * call.
 *
 * @param cos          Array of CoS handles
 * @param num          Number of CoSes to destroy
 *
 * @retval Number of CoSes actually destroyed (1 ... num)
 * @retval <0 on failure
 */
int odp_cos_destroy_multi(odp_cos_t cos[], int num);

/**
 * Assign a queue for a class-of-service
 *
 * Action of the given CoS may not be ODP_COS_ACTION_DROP.
 *
 * @param cos          CoS handle
 * @param queue        Handle of the queue where all packets of this specific
 *                     class of service will be enqueued. Must not be
 *                     ODP_QUEUE_INVALID.
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cos_queue_set(odp_cos_t cos, odp_queue_t queue);

/**
* Get the queue associated with the specific class-of-service
*
* @param cos           CoS handle
*
* @retval Queue handle associated with the given class-of-service
* @retval ODP_QUEUE_INVALID on failure, or if there are multiple queues, or if
*         the CoS action is ODP_COS_ACTION_DROP.
*/
odp_queue_t odp_cos_queue(odp_cos_t cos);

/**
 * Get the number of queues linked with the specific class-of-service
 *
 * @param cos          CoS handle
 *
 * @return Number of queues linked with the class-of-service.
 */
uint32_t odp_cls_cos_num_queue(odp_cos_t cos);

/**
 * Get the list of queue associated with the specific class-of-service
 *
 * @param      cos     CoS handle
 * @param[out] queue   Array of queue handles associated with
 *                     the class-of-service.
 * @param      num     Maximum number of queue handles to output.
 *
 * @return Number of queues linked with CoS
 * @retval 0 on failure
 */
uint32_t odp_cls_cos_queues(odp_cos_t cos, odp_queue_t queue[], uint32_t num);

/**
 * Get statistics for a CoS
 *
 * The statistics counters are incremented for packets classified to the
 * given CoS.
 *
 * Counters that are not supported are set to zero.
 *
 * It's implementation defined if odp_pktio_stats_reset() call affects these
 * counters.
 *
 * @param      cos     CoS handle
 * @param[out] stats   Statistics structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cls_cos_stats(odp_cos_t cos, odp_cls_cos_stats_t *stats);

/**
 * Get statistics for a queue assigned to a CoS
 *
 * The statistics counters are incremented only for packets originating from the
 * given CoS. Queue handles can be requested with odp_cos_queue() and
 * odp_cls_cos_queues().
 *
 * Counters not supported by the queue are set to zero.
 *
 * It's implementation defined if odp_pktio_stats_reset() call affects these
 * counters.
 *
 * @param      cos     CoS handle
 * @param      queue   Queue handle
 * @param[out] stats   Statistics structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cls_queue_stats(odp_cos_t cos, odp_queue_t queue,
			odp_cls_queue_stats_t *stats);

/**
 * Initialize packet matching rule parameters
 *
 * Initialize an odp_pmr_param_t to its default values for all fields
 *
 * @param param        Address of the odp_pmr_param_t to be initialized
 */
void odp_cls_pmr_param_init(odp_pmr_param_t *param);

/**
 * Initialize packet matching rule creation option
 *
 * Initialize an odp_pmr_create_opt_t to its default values for all fields
 *
 * @param opt       Address of the odp_pmr_create_opt_t to be initialized
 */
void odp_cls_pmr_create_opt_init(odp_pmr_create_opt_t *opt);

/**
 * Create Packet Matching Rule (PMR)
 *
 * Creates a PMR between source and destination Class of Service (CoS). A packet arriving to
 * a CoS is matched against all the PMRs that define it as their source CoS. A PMR match moves
 * the packet from the source to the destination CoS.
 *
 * This function creates PMRs of priority zero. Use odp_cls_pmr_create_opt() to create PMRs of
 * any priority. If multiple PMRs of the same priority match the packet, it is implementation
 * specific which PMR is selected.
 *
 * A composite PMR is created when PMR parameters define more than one term. A composite PMR is
 * considered to match only if a packet matches with all its terms. It is implementation specific
 * which term combinations are supported as composite PMRs. When creating a composite PMR,
 * application should check the return value and perform appropriate fallback actions if the create
 * call returns failure. See odp_cls_capability_t::max_pmr and
 * odp_cls_capability_t::max_terms_per_pmr for related capabilities.
 *
 * Use odp_cls_pmr_param_init() to initialize parameters into their default values.
 *
 * PMRs created with this function are equivant to PMRs created through odp_cls_pmr_create_opt()
 * with the same PMR terms and with all additional options set to their default values (e.g.
 * CLS mark is set to zero in all matching packets).
 *
 * @param terms        Array of odp_pmr_param_t entries, one entry per term
 * @param num_terms    Number of terms in the PMR.
 * @param src_cos      source CoS handle
 * @param dst_cos      destination CoS handle
 *
 * @return PMR handle on success
 * @retval ODP_PMR_INVALID on failure
 */
odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
			     odp_cos_t src_cos, odp_cos_t dst_cos);

/**
 * Create a packet matching rule with options
 *
 * Similar to odp_cls_pmr_create() function with additional PMR creation
 * options specified through odp_pmr_create_opt_t.
 *
 * Use odp_cls_pmr_create_opt_init() to initialize options into their default
 * values.
 *
 * @param opt	       points to PMR create options
 * @param src_cos      source CoS handle
 * @param dst_cos      destination CoS handle
 *
 * @return Handle to the Packet Match Rule.
 * @retval ODP_PMR_INVALID on failure
 *
 */
odp_pmr_t odp_cls_pmr_create_opt(const odp_pmr_create_opt_t *opt,
				 odp_cos_t src_cos, odp_cos_t dst_cos);

/**
 * Create multiple packet matching rules
 *
 * Otherwise like odp_cls_pmr_create_opt(), but creates multiple rules with a
 * single call. The output PMR handles are written in the same order as input
 * parameters. A single odp_cls_pmr_create_multi() call is equivalent to calling
 * odp_cls_pmr_create_opt() 'num' times in row.
 *
 * Each parameter array must contain 'num' elements.
 *
 * @param      opt      Array of PMR create options
 * @param      src_cos  Array of source CoS handles
 * @param      dst_cos  Array of destination CoS handles
 * @param[out] pmr      Array of PMR handles for output
 * @param      num      Number of packet matching rules to create
 *
 * @return Number of PMRs actually created (0 ... num)
 * @retval <0 on failure
 */
int odp_cls_pmr_create_multi(const odp_pmr_create_opt_t opt[],
			     odp_cos_t src_cos[], odp_cos_t dst_cos[],
			     odp_pmr_t pmr[], int num);

/**
 * Function to destroy a packet match rule
 *
 * Destroying a PMR removes the link between the source and destination
 * class of service and this PMR will no longer be applied for packets arriving
 * at the source class of service. All the resources associated with the PMR
 * will be released but the class of service will remain intact.
 *
 * Depending on the implementation details, destroying a composite rule
 * may not guarantee the availability of hardware resources to create the
 * same or essentially similar rule.
 *
 * @param pmr       Handle of the PMR to be destroyed
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cls_pmr_destroy(odp_pmr_t pmr);

/**
 * Destroy multiple packet matching rules
 *
 * Otherwise like odp_cls_pmr_destroy(), but destroys multiple PMRs with a
 * single call.
 *
 * @param pmr       Array of PMR handles
 * @param num       Number of PMRs to destroy
 *
 * @retval Number of PMRs actually destroyed (1 ... num)
 * @retval <0 on failure
 */
int odp_cls_pmr_destroy_multi(odp_pmr_t pmr[], int num);

/**
* Assigns a packet pool for a specific class of service
*
* All the packets belonging to the given class of service will
* be allocated from the assigned packet pool.
* The packet pool associated with class of service will supersede the
* packet pool associated with the pktio interface.
*
* @param cos        CoS handle
* @param pool_id    Packet pool handle
*
* @retval  0 on success
* @retval <0 on failure
*/
int odp_cls_cos_pool_set(odp_cos_t cos, odp_pool_t pool_id);

/**
* Get the pool associated with the given class of service
*
* @param cos        CoS handle
*
* @retval pool handle of the associated pool
* @retval ODP_POOL_INVALID on failure, or if the pool has not been set
*/
odp_pool_t odp_cls_cos_pool(odp_cos_t cos);

/**
 * Get printable value for an odp_cos_t
 *
 * @param cos       CoS handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_cos_t handle.
 */
uint64_t odp_cos_to_u64(odp_cos_t cos);

/**
 * Get printable value for an odp_pmr_t
 *
 * @param pmr          odp_pmr_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pmr_t handle.
 */
uint64_t odp_pmr_to_u64(odp_pmr_t pmr);

/**
 * Print classifier info
 *
 * Print implementation defined information about classifier. The information is
 * intended to be used for debugging.
 */
void odp_cls_print_all(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
