/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Packet IO types
 */

#ifndef ODP_API_SPEC_PACKET_IO_TYPES_H_
#define ODP_API_SPEC_PACKET_IO_TYPES_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/deprecated.h>
#include <odp/api/packet_types.h>
#include <odp/api/packet_io_stats.h>
#include <odp/api/pool_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/reassembly.h>
#include <odp/api/std_types.h>

/** @addtogroup odp_packet_io
 *  @{
 */

/**
 * @typedef odp_pktio_t
 * Packet IO handle
 */

/**
 * @typedef odp_pktin_queue_t
 * Direct packet input queue handle
 */

/**
 * @typedef odp_pktout_queue_t
 * Direct packet output queue handle
 */

/**
 * @typedef odp_lso_profile_t
 * LSO profile handle
 */

/**
 * @def ODP_PKTIO_INVALID
 * Invalid packet IO handle
 */

/**
 * @def ODP_LSO_PROFILE_INVALID
 * Invalid LSO profile handle
 */

/**
 * @def ODP_PKTIO_MACADDR_MAXSIZE
 * Minimum size of output buffer for odp_pktio_mac_addr()
 * Actual MAC address sizes may be different.
 */

/**
 * @def ODP_PKTIN_NO_WAIT
 * Do not wait on packet input
 */

/**
 * @def ODP_PKTOUT_MAX_QUEUES
 * Maximum number of packet output queues supported by the API. Use
 * odp_pktio_capability() to check the maximum number of queues per interface.
 */

/**
 * Packet input mode
 */
typedef enum odp_pktin_mode_t {
	/** Direct packet input from the interface */
	ODP_PKTIN_MODE_DIRECT = 0,
	/** Packet input through scheduler and scheduled event queues */
	ODP_PKTIN_MODE_SCHED,
	/** Packet input through plain event queues */
	ODP_PKTIN_MODE_QUEUE,
	/** Application will never receive from this interface */
	ODP_PKTIN_MODE_DISABLED
} odp_pktin_mode_t;

/**
 * Packet output mode
 */
typedef enum odp_pktout_mode_t {
	/** Direct packet output on the interface */
	ODP_PKTOUT_MODE_DIRECT = 0,
	/** Packet output through event queues */
	ODP_PKTOUT_MODE_QUEUE,
	/** Packet output through traffic manager API */
	ODP_PKTOUT_MODE_TM,
	/** Application will never send to this interface */
	ODP_PKTOUT_MODE_DISABLED
} odp_pktout_mode_t;

/**
 * Packet input hash protocols
 *
 * The list of protocol header field combinations, which are included into
 * packet input hash calculation.
 */
typedef union odp_pktin_hash_proto_t {
	/** Protocol header fields for hashing */
	struct {
		/** IPv4 addresses and UDP port numbers */
		uint32_t ipv4_udp : 1;
		/** IPv4 addresses and TCP port numbers */
		uint32_t ipv4_tcp : 1;
		/** IPv4 addresses */
		uint32_t ipv4     : 1;
		/** IPv6 addresses and UDP port numbers */
		uint32_t ipv6_udp : 1;
		/** IPv6 addresses and TCP port numbers */
		uint32_t ipv6_tcp : 1;
		/** IPv6 addresses */
		uint32_t ipv6     : 1;
	} proto;

	/** All bits of the bit field structure
	 *
	 *  This field can be used to set/clear all bits, or to perform bitwise
	 *  operations over those. */
	uint32_t all_bits;
} odp_pktin_hash_proto_t;

/**
 * Packet IO operation mode
 */
typedef enum odp_pktio_op_mode_t {
	/** Multithread safe operation
	  *
	  * Direct packet IO operation (recv or send) is multithread safe. Any
	  * number of application threads may perform the operation
	  * concurrently. */
	ODP_PKTIO_OP_MT = 0,

	/** Not multithread safe operation
	  *
	  * Direct packet IO operation (recv or send) may not be multithread
	  * safe. Application ensures synchronization between threads so that
	  * simultaneously only single thread attempts the operation on
	  * the same (pktin or pktout) queue. */
	ODP_PKTIO_OP_MT_UNSAFE

} odp_pktio_op_mode_t;

/**
 * Packet input queue parameters override
 */
typedef struct odp_pktin_queue_param_ovr_t {
	/** Override for schedule group in odp_schedule_param_t
	  *
	  * This parameter is considered only when queue type is
	  * ODP_QUEUE_TYPE_SCHED. */
	odp_schedule_group_t group;
} odp_pktin_queue_param_ovr_t;

/**
 * Packet input vector configuration
 */
typedef struct odp_pktin_vector_config_t {
	/** Enable packet input vector
	 *
	 * When true, packet input vector is enabled and configured with vector
	 * config parameters. Otherwise, packet input vector configuration
	 * parameters are ignored. When vectors are enabled, packets may
	 * be delivered both as packet vector events and packet events.
	 * The default value is false.
	 */
	odp_bool_t enable;

	/** Vector pool
	 *
	 * Vector pool to allocate the vectors to hold packets.
	 * The pool must have been created with the ODP_POOL_VECTOR type.
	 */
	odp_pool_t pool;

	/** Maximum time to wait for packets
	 *
	 * Maximum timeout in nanoseconds to wait for the producer to form the
	 * vector of packet events (odp_packet_vector_t). This value should be
	 * in the range of odp_pktin_vector_capability_t::min_tmo_ns to
	 * odp_pktin_vector_capability_t::max_tmo_ns.
	 */
	uint64_t max_tmo_ns;

	/** Maximum number of packets in a vector
	 *
	 * The packet input subsystem forms packet vector events when either
	 * it reaches odp_pktin_vector_config_t::max_tmo_ns or producer reaches
	 * max_size packets. This value should be in the range of
	 * odp_pktin_vector_capability_t::min_size to
	 * odp_pktin_vector_capability_t::max_size.
	 *
	 * @note The maximum number of packets this vector can hold is defined
	 * by odp_pool_param_t::vector::max_size with odp_pktin_vector_config_t::pool.
	 * The max_size should not be greater than odp_pool_param_t::vector::max_size.
	 */
	uint32_t max_size;

} odp_pktin_vector_config_t;

/**
 * Packet input queue parameters
 */
typedef struct odp_pktin_queue_param_t {
	/** Operation mode
	  *
	  * The default value is ODP_PKTIO_OP_MT. Application may enable
	  * performance optimization by defining ODP_PKTIO_OP_MT_UNSAFE when
	  * applicable. */
	odp_pktio_op_mode_t op_mode;

	/** Enable classifier
	  *
	  * * 0: Classifier is disabled (default)
	  * * 1: Classifier is enabled. Use classifier to direct incoming
	  *      packets into pktin event queues. Classifier can be enabled
	  *      only in ODP_PKTIN_MODE_SCHED and ODP_PKTIN_MODE_QUEUE modes.
	  *      Both classifier and hashing cannot be enabled simultaneously
	  *      ('hash_enable' must be 0). */
	odp_bool_t classifier_enable;

	/** Enable flow hashing
	  *
	  * * 0: Do not hash flows (default)
	  * * 1: Enable flow hashing. Use flow hashing to spread incoming
	  *      packets into input queues. Hashing can be enabled in all
	  *      modes. Both classifier and hashing cannot be enabled
	  *      simultaneously ('classifier_enable' must be 0). */
	odp_bool_t hash_enable;

	/** Protocol field selection for hashing
	  *
	  * Multiple protocols can be selected. Ignored when 'hash_enable' is
	  * zero. The default value is all bits zero. */
	odp_pktin_hash_proto_t hash_proto;

	/** Number of input queues to be created
	  *
	  * When classifier is enabled in odp_pktin_queue_config() this
	  * value is ignored, otherwise at least one queue is required.
	  * More than one input queues require flow hashing configured.
	  * The maximum value is defined by pktio capability 'max_input_queues'.
	  * Queue type is defined by the input mode. The default value is 1. */
	uint32_t num_queues;

	/** Queue parameters
	  *
	  * These are used for input queue creation in ODP_PKTIN_MODE_QUEUE
	  * or ODP_PKTIN_MODE_SCHED modes. Scheduler parameters are considered
	  * only in ODP_PKTIN_MODE_SCHED mode. Default values are defined in
	  * odp_queue_param_t documentation. The type field is ignored
	  * and the queue type is deduced from the pktio input mode.
	  * When classifier is enabled in odp_pktin_queue_config() this
	  * value is ignored. */
	odp_queue_param_t queue_param;

	/** Queue parameters override
	  *
	  * When the override array is defined, the same parameter value
	  * in 'queue_param' is ignored and these per queue parameter
	  * values are used instead. Array elements are used in order
	  * (i.e. the first queue gets parameters from the first array
	  * element, etc).
	  * Must point to an array of num_queues elements or NULL to
	  * disable queue parameters override. The default value is
	  * NULL.
	  */
	odp_pktin_queue_param_ovr_t *queue_param_ovr;

	/** Packet input vector configuration */
	odp_pktin_vector_config_t vector;

} odp_pktin_queue_param_t;

/**
 * Packet output queue parameters
 *
 * These parameters are used in ODP_PKTOUT_MODE_DIRECT and
 * ODP_PKTOUT_MODE_QUEUE modes.
 */
typedef struct odp_pktout_queue_param_t {
	/** Operation mode
	  *
	  * The default value is ODP_PKTIO_OP_MT. Application may enable
	  * performance optimization by defining ODP_PKTIO_OP_MT_UNSAFE when
	  * applicable. */
	odp_pktio_op_mode_t op_mode;

	/** Number of output queues to be created. The value must be between
	  * 1 and interface capability. The default value is 1. */
	uint32_t num_queues;

	/** Output queue size array
	  *
	  * An array containing queue sizes for each 'num_queues' output queues.
	  * The value of zero means implementation specific default size.
	  * Nonzero values must be between 'min_output_queue_size' and
	  * 'max_output_queue_size' capabilities. The implementation may
	  * round-up given values. The default value is zero.
	  */
	uint32_t queue_size[ODP_PKTOUT_MAX_QUEUES];

} odp_pktout_queue_param_t;

/**
 * Packet IO parameters
 *
 * Packet IO interface level parameters. Use odp_pktio_param_init() to
 * initialize the structure with default values.
 */
typedef struct odp_pktio_param_t {
	/** Packet input mode
	  *
	  * The default value is ODP_PKTIN_MODE_DIRECT. */
	odp_pktin_mode_t in_mode;

	/** Packet output mode
	  *
	  * The default value is ODP_PKTOUT_MODE_DIRECT. */
	odp_pktout_mode_t out_mode;

} odp_pktio_param_t;

/**
 * Packet input configuration options bit field
 *
 * Packet input configuration options listed in a bit field structure. Packet
 * input timestamping may be enabled for all packets or at least for those that
 * belong to time synchronization protocol (PTP).
 *
 * Packet input checksum checking may be enabled or disabled. When it is
 * enabled, implementation will attempt to verify checksum correctness on
 * incoming packets and depending on drop configuration either deliver erroneous
 * packets with appropriate flags set (e.g. odp_packet_has_l3_error(),
 * odp_packet_l3_chksum_status()) or drop those. When packet dropping is
 * enabled, application will never receive a packet with the specified error
 * and may avoid to check the error flag.
 *
 * If checksum checking is enabled, IPv4 header checksum checking is always
 * done for packets that do not have IP options and L4 checksum checking
 * is done for unfragmented packets that do not have IPv4 options or IPv6
 * extension headers. In other cases checksum checking may or may not
 * be done. For example, L4 checksum of fragmented packets is typically
 * not checked.
 *
 * IPv4 checksum checking may be enabled only when parsing level is
 * ODP_PROTO_LAYER_L3 or higher. Similarly, L4 level checksum checking
 * may be enabled only with parsing level ODP_PROTO_LAYER_L4 or higher.
 *
 * Whether checksum checking was done and whether a checksum was correct
 * can be queried for each received packet with odp_packet_l3_chksum_status()
 * and odp_packet_l4_chksum_status().
 */
typedef union odp_pktin_config_opt_t {
	/** Option flags */
	struct {
		/** Timestamp all packets on packet input */
		uint64_t ts_all        : 1;

		/** Timestamp (at least) IEEE1588 / PTP packets
		  * on packet input */
		uint64_t ts_ptp        : 1;

		/** Strip VLAN tags of received packets so that the ODP
		 *  application sees untagged packets. VLAN ID is saved
		 *  in packet metadata and can be read using
		 *  odp_packet_vlan_info().
		 *
		 *  This removes only the outermost VLAN tag and only if
		 *  its ethertype is 0x8100.
		 *
		 *  VLAN stripping is done as a last step of packet input
		 *  processing just before the application gets the packet.
		 *  This means that packet parsing and classification is
		 *  done with the VLAN tag still in the packet. The has_vlan
		 *  and has_qinq packet flags are set at packet parsing
		 *  before the stripping. Retained L2 headers in inline
		 *  IPsec processing include the VLAN tag.
		 *
		 *  Support for VLAN strip offload must be checked from
		 *  odp_pktio_capability_t::vlan_offload returned by
		 *  odp_pktio_capability(). This flag is used only for
		 *  configuration.
		 */
		uint64_t vlan_strip    : 1;

		/** Check IPv4 header checksum on packet input */
		uint64_t ipv4_chksum   : 1;

		/** Check UDP checksum on packet input */
		uint64_t udp_chksum    : 1;

		/** Check TCP checksum on packet input */
		uint64_t tcp_chksum    : 1;

		/** Check SCTP checksum on packet input */
		uint64_t sctp_chksum   : 1;

		/** Drop packets with an IPv4 error on packet input */
		uint64_t drop_ipv4_err : 1;

		/** Drop packets with an IPv6 error on packet input */
		uint64_t drop_ipv6_err : 1;

		/** Drop packets with a UDP error on packet input */
		uint64_t drop_udp_err  : 1;

		/** Drop packets with a TCP error on packet input */
		uint64_t drop_tcp_err  : 1;

		/** Drop packets with a SCTP error on packet input */
		uint64_t drop_sctp_err : 1;

	} bit;

	/** All bits of the bit field structure
	  *
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint64_t all_bits;
} odp_pktin_config_opt_t;

/**
 * Packet output configuration options bit field
 *
 * Packet output configuration options listed in a bit field structure. Packet
 * output checksum insertion may be enabled or disabled (e.g. ipv4_chksum_ena):
 *
 *  0: Disable checksum insertion. Application will not request checksum
 *     insertion for any packet. This is the default value for xxx_chksum_ena
 *     bits.
 *  1: Enable checksum insertion. Application will request checksum insertion
 *     for some packets.
 *
 * When checksum insertion is enabled, application may use configuration options
 * to set the default behaviour on packet output (e.g. ipv4_chksum):
 *
 *  0: Do not insert checksum by default. This is the default value for
 *     xxx_chksum bits.
 *  1: Calculate and insert checksum by default.
 *
 * These defaults may be overridden on per packet basis using e.g.
 * odp_packet_l4_chksum_insert().
 *
 * For correct operation, packet metadata must provide valid offsets and type
 * flags for the appropriate layer 3 and layer 4 protocols.  L3 and L4 offsets
 * can be updated with odp_packet_l3_offset_set() and odp_packet_l4_offset_set()
 * calls. L3 and L4 type flags can be updated using odp_packet_has_*_set() calls
 * For example, UDP checksum calculation needs both L3 and L4 types (IP and UDP) and
 * L3 and L4 offsets (to access IP and UDP headers), while IP checksum
 * calculation only needs L3 type (IP) and L3 offset (to access IP header).
 * When application (e.g. a switch) does not modify L3/L4 data and thus checksum
 * does not need to be updated, checksum insertion should be disabled for optimal
 * performance.
 *
 * UDP, TCP and SCTP checksum insertion must not be requested for IP fragments.
 * Use checksum override function (odp_packet_l4_chksum_insert()) to disable
 * checksumming when sending a fragment through a packet IO interface that has
 * the relevant L4 checksum insertion enabled.
 *
 * Result of checksum insertion at packet output is undefined if the protocol
 * headers required for checksum calculation are not well formed. Packet must
 * contain at least as many data bytes after L3/L4 offsets as the headers
 * indicate. Other data bytes of the packet are ignored for the checksum
 * insertion.
 */
typedef union odp_pktout_config_opt_t {
	/** Option flags for packet output */
	struct {
		/** Enable Tx timestamp capture */
		uint64_t ts_ena : 1;

		/** Enable IPv4 header checksum insertion */
		uint64_t ipv4_chksum_ena : 1;

		/** Enable UDP checksum insertion */
		uint64_t udp_chksum_ena  : 1;

		/** Enable TCP checksum insertion */
		uint64_t tcp_chksum_ena  : 1;

		/** Enable SCTP checksum insertion */
		uint64_t sctp_chksum_ena : 1;

		/** Insert IPv4 header checksum by default */
		uint64_t ipv4_chksum     : 1;

		/** Insert UDP checksum on packet by default */
		uint64_t udp_chksum      : 1;

		/** Insert TCP checksum on packet by default */
		uint64_t tcp_chksum      : 1;

		/** Insert SCTP checksum on packet by default */
		uint64_t sctp_chksum     : 1;

		/** Packet references not used on packet output
		 *
		 * When set, application indicates that it will not transmit
		 * packet references on this packet IO interface.
		 * Since every ODP implementation supports it, it is always
		 * ok to set this flag.
		 *
		 * 0: Packet references may be transmitted on the
		 *    interface (the default value).
		 * 1: Packet references will not be transmitted on the
		 *    interface.
		 */
		uint64_t no_packet_refs  : 1;

		/** Enable packet aging and drop
		 *
		 * 0: application will not request packet aging (default)
		 * 1: application may request packet aging
		 */
		uint64_t aging_ena  : 1;

		/** Enable packet transmit completion event requests
		 *
		 * Use pktio capability tx_compl to check if TX completion events are supported.
		 *
		 * 0: Application will not request packet TX completion events (default)
		 * 1: Application may request packet TX completion events
		 */
		uint64_t tx_compl_ena : 1;

		/** Enable packet protocol stats update */
		uint64_t proto_stats_ena : 1;

	} bit;

	/** All bits of the bit field structure
	  *
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint64_t all_bits;
} odp_pktout_config_opt_t;

/**
 * Parser configuration
 */
typedef struct odp_pktio_parser_config_t {
	/** Protocol parsing level in packet input
	  *
	  * Application requires that protocol headers in a packet are checked
	  * up to this layer during packet input. Use ODP_PROTO_LAYER_ALL for
	  * all layers. Packet metadata for this and all preceding layers are
	  * set. In addition, offset (and pointer) to the next layer is set.
	  * Other layer/protocol specific metadata have undefined values.
	  *
	  * The default value is ODP_PROTO_LAYER_ALL. */
	odp_proto_layer_t layer;

} odp_pktio_parser_config_t;

/**
 * Packet IO configuration options
 *
 * Packet IO interface level configuration options. Use odp_pktio_capability()
 * to see which options are supported by the implementation.
 * Use odp_pktio_config_init() to initialize the structure with default values.
 */
typedef struct odp_pktio_config_t {
	/** Packet input configuration options bit field
	 *
	 *  Default value for all bits is zero. */
	odp_pktin_config_opt_t pktin;

	/** Packet output configuration options bit field
	 *
	 *  Default value for all bits is zero. */
	odp_pktout_config_opt_t pktout;

	/** Packet input parser configuration */
	odp_pktio_parser_config_t parser;

	/** Interface loopback mode
	 *
	 * In this mode the packets sent out through the interface is
	 * looped back to input of the same interface. Supporting loopback mode
	 * is an optional feature per interface and should be queried in the
	 * interface capability before enabling the same.
	 *
	 * Default value is false.
	 */
	odp_bool_t enable_loop;

	/** Inbound IPSEC inlined with packet input
	 *
	 *  Enable/disable inline inbound IPSEC operation. When enabled packet
	 *  input directs all IPSEC packets automatically to IPSEC inbound
	 *  processing. IPSEC configuration (through IPSEC API) must be done
	 *  before enabling this feature in pktio.
	 *  Packets that are not (recognized as) IPSEC are processed
	 *  according to the packet input configuration.
	 *
	 *  0: Disable inbound IPSEC inline operation (default)
	 *  1: Enable inbound IPSEC inline operation
	 *
	 *  @see odp_ipsec_config(), odp_ipsec_sa_create()
	 */
	odp_bool_t inbound_ipsec;

	/** Outbound IPSEC inlined with packet output
	 *
	 *  Enable/disable inline outbound IPSEC operation. When enabled IPSEC
	 *  outbound processing can send outgoing IPSEC packets directly
	 *  to the pktio interface for output. IPSEC configuration is done
	 *  through the IPSEC API.
	 *
	 *  Support of outbound IPSEC inline operation with traffic manager
	 *  (ODP_PKTOUT_MODE_TM) can be queried with odp_ipsec_capability().
	 *
	 * * 0: Disable outbound IPSEC inline operation (default)
	 * * 1: Enable outbound IPSEC inline operation
	 *
	 *  @see odp_ipsec_config(), odp_ipsec_sa_create()
	 *  odp_ipsec_out_inline()
	 */
	odp_bool_t outbound_ipsec;

	/** Enable Large Send Offload (LSO)
	 *
	 *  Enables LSO on the interface. Use LSO capabilities (odp_lso_capability_t) to check if
	 *  the interface supports LSO (in the selected packet output mode). LSO cannot be enabled
	 *  in ODP_PKTOUT_MODE_QUEUE mode. Also, LSO operation cannot be combined with IPSEC on
	 *  packet output.
	 *
	 *  Application requests LSO for outgoing packets with odp_pktout_send_lso() or
	 *  odp_tm_enq_multi_lso(). Other packet output calls ignore LSO metadata in packets.
	 *
	 *  0: Application will not use LSO (default)
	 *  1: Application will use LSO
	 */
	odp_bool_t enable_lso;

	/** Packet input reassembly configuration */
	odp_reass_config_t reassembly;

} odp_pktio_config_t;

/**
 * Packet IO set operations
 *
 * Supported packet IO interface set operations listed in a bit field structure.
 */
typedef union odp_pktio_set_op_t {
	/** Operation flags */
	struct {
		/** Promiscuous mode */
		uint32_t promisc_mode : 1;
		/** MAC address  */
		uint32_t mac_addr : 1;
		/** Per port header offset(skip)set */
		uint32_t skip_offset : 1;
		/** Maximum frame length */
		uint32_t maxlen : 1;
	} op;
	/** All bits of the bit field structure.
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint32_t all_bits;
} odp_pktio_set_op_t;

/** Maximum number of custom LSO fields supported by ODP API */
#define ODP_LSO_MAX_CUSTOM 8

/** LSO custom modification options */
typedef enum odp_lso_modify_t {
	/** Add current segment number. Numbering starts from zero. */
	ODP_LSO_ADD_SEGMENT_NUM = 0x1,

	/** Add number of payload bytes in the segment */
	ODP_LSO_ADD_PAYLOAD_LEN = 0x2,

	/** Add number of payload bytes in all previous segments */
	ODP_LSO_ADD_PAYLOAD_OFFSET = 0x4

} odp_lso_modify_t;

/** LSO protocol options
 *
 *  An LSO operation may perform segmentation on these protocols.
 */
typedef enum odp_lso_protocol_t {
	/** Protocol not selected. */
	ODP_LSO_PROTO_NONE = 0,

	/** Custom protocol. LSO performs only custom field updates to the packet headers. */
	ODP_LSO_PROTO_CUSTOM,

	/** LSO performs IPv4 fragmentation.
	 *
	 *  IP header length and checksum fields are updated. IP fragmentation related fields are
	 *  filled and IPv4 Identification field value is copied from the original packet. */
	ODP_LSO_PROTO_IPV4,

	/** LSO performs IPv6 fragmentation. */
	ODP_LSO_PROTO_IPV6,

	/** LSO performs TCP segmentation on top of IPv4.
	 *
	 *  IP header length and checksum fields are updated. IP fragmentation is not performed
	 *  and IPv4 Don't Fragment bit is not set. Unique IPv4 Identification field values
	 *  are generated. Those are usually increments of the IPv4 ID field value in the packet.
	 */
	ODP_LSO_PROTO_TCP_IPV4,

	/** LSO performs TCP segmentation on top of IPv6. */
	ODP_LSO_PROTO_TCP_IPV6,

	/** LSO performs SCTP segmentation on top of IPv4. */
	ODP_LSO_PROTO_SCTP_IPV4,

	/** LSO performs SCTP segmentation on top of IPv6. */
	ODP_LSO_PROTO_SCTP_IPV6

} odp_lso_protocol_t;

/** Large Send Offload (LSO) capabilities */
typedef struct odp_lso_capability_t {
	/** Maximum number of LSO profiles. When zero, LSO is not supported. */
	uint32_t max_profiles;

	/** Maximum number of LSO profiles per packet IO interface. When zero, LSO is not
	 *  supported by the interface. */
	uint32_t max_profiles_per_pktio;

	/** Maximum number of segments in an input packet. When one, LSO operation accepts only
	 *  non-segmented packets as input. */
	uint32_t max_packet_segments;

	/** Maximum number of segments an LSO operation may create. This implies that
	 *  the maximum supported input packet payload size for an LSO operation is
	 *  max_segments * max_payload_len bytes. */
	uint32_t max_segments;

	/** Maximum payload length per an LSO generated packet (in bytes). This is the maximum value
	 *  for max_payload_len in odp_packet_lso_opt_t. */
	uint32_t max_payload_len;

	/** Maximum supported offset to the packet payload (in bytes). This is the maximum value
	 *  for payload_offset in odp_packet_lso_opt_t. */
	uint32_t max_payload_offset;

	/** Supported LSO custom modification options */
	struct {
		/** ODP_LSO_ADD_SEGMENT_NUM support */
		uint16_t add_segment_num:1;

		/** ODP_LSO_ADD_PAYLOAD_LEN support */
		uint16_t add_payload_len:1;

		/** ODP_LSO_ADD_PAYLOAD_OFFSET support */
		uint16_t add_payload_offset:1;

	} mod_op;

	/** Maximum number of custom fields supported per LSO profile. When zero, custom
	 *  fields are not supported. */
	uint8_t max_num_custom;

	/** Supported LSO protocol options */
	struct {
		/** ODP_LSO_PROTO_CUSTOM support */
		uint32_t custom:1;

		/** ODP_LSO_PROTO_IPV4 support */
		uint32_t ipv4:1;

		/** ODP_LSO_PROTO_IPV6 support */
		uint32_t ipv6:1;

		/** ODP_LSO_PROTO_TCP_IPV4 support */
		uint32_t tcp_ipv4:1;

		/** ODP_LSO_PROTO_TCP_IPV6 support */
		uint32_t tcp_ipv6:1;

		/** ODP_LSO_PROTO_SCTP_IPV4 support */
		uint32_t sctp_ipv4:1;

		/** ODP_LSO_PROTO_SCTP_IPV6 support */
		uint32_t sctp_ipv6:1;

	} proto;

} odp_lso_capability_t;

/**
 * Packet input vector capabilities
 */
typedef struct odp_pktin_vector_capability_t {
	/** Packet input vector availability */
	odp_support_t supported;

	/** Maximum number of packets that can be accumulated into a packet
	 *  vector by a producer
	 *
	 * odp_pktin_vector_config_t::max_size should not be greater than this
	 * value. */
	uint32_t max_size;

	/** Minimum value allowed to be configured to
	 * odp_pktin_vector_config_t::max_size */
	uint32_t min_size;

	/** Maximum timeout in nanoseconds for the producer to wait for the
	 *  vector of packets
	 *
	 * odp_pktin_vector_config_t::max_tmo_ns should not be greater than this
	 * value. */
	uint64_t max_tmo_ns;

	/** Minimum value allowed to be configured to
	 * odp_pktin_vector_config_t::max_tmo_ns */
	uint64_t min_tmo_ns;

} odp_pktin_vector_capability_t;

/**
 * VLAN offload capabilities
 */
typedef struct odp_vlan_offload_capability_t {
	/** Supported offloads */
	struct {
		/** VLAN strip in packet input */
		uint32_t vlan_strip:1;
	} offloads;

} odp_vlan_offload_capability_t;

/**
 * Packet IO capabilities
 *
 * Note that interface capabilities may differ between packet output modes. For example,
 * LSO may not be supported in ODP_PKTOUT_MODE_TM mode, while it is supported in
 * ODP_PKTOUT_MODE_DIRECT mode.
 */
typedef struct odp_pktio_capability_t {
	/** Maximum number of input queues */
	uint32_t max_input_queues;

	/** Maximum number of output queues
	 *
	 * Value does not exceed ODP_PKTOUT_MAX_QUEUES. */
	uint32_t max_output_queues;

	/** Minimum output queue size
	 *
	 *  Zero if configuring queue size is not supported. */
	uint32_t min_output_queue_size;

	/** Maximum output queue size
	 *
	 *  Zero if configuring queue size is not supported. */
	uint32_t max_output_queue_size;

	/** Supported pktio configuration options */
	odp_pktio_config_t config;

	/** Supported set operations
	 *
	 * A bit set to one indicates a supported operation. All other bits are
	 * set to zero. */
	odp_pktio_set_op_t set_op;

	/** Packet input vector capability */
	odp_pktin_vector_capability_t vector;

	/** LSO capabilities */
	odp_lso_capability_t lso;

	/** Supported frame lengths for odp_pktio_maxlen_set()
	 *
	 * A frame length value of zero indicates an unsupported operation. */
	struct {
		/** Equal maximum frame length for both packet input and output
		 *
		 * When set, the same maximum frame length value has to be used
		 * for both input and output directions. */
		odp_bool_t equal;
		/** Minimum valid value for 'maxlen_input' */
		uint32_t min_input;
		/** Maximum valid value for 'maxlen_input' */
		uint32_t max_input;
		/** Minimum valid value for 'maxlen_output' */
		uint32_t min_output;
		/** Maximum valid value for 'maxlen_output' */
		uint32_t max_output;
	} maxlen;

	/**
	 * Max Tx aging timeout in nano seconds supported when packet aging
	 * feature is supported.
	 *
	 * 0: aging is not supported
	 * >0: maximum aging timeout supported in nanoseconds
	 */
	uint64_t max_tx_aging_tmo_ns;

	/** Supported packet Tx completion options */
	struct {
		/**
		 * Scheduled queue support
		 *
		 * This defines whether schedule queues are supported for receiving Tx
		 * completion events.
		 *
		 * 0: Scheduled queues are not supported for receiving Tx completion events.
		 * 1: Scheduled queues are supported for receiving Tx completion events.
		 * @see odp_packet_tx_compl_request()
		 */
		odp_bool_t queue_type_sched;

		/**
		 * Plain queue support
		 *
		 * This defines whether plain queues are supported for receiving Tx
		 * completion events.
		 *
		 * 0: Plain queues are not supported for receiving Tx completion events.
		 * 1: Plain queues are supported for receiving Tx completion events.
		 * @see odp_packet_tx_compl_request()
		 */
		odp_bool_t queue_type_plain;

		/** ODP_PACKET_TX_COMPL_ALL supported */
		uint32_t mode_all:1;

	} tx_compl;

	/** Packet input reassembly capability */
	odp_reass_capability_t reassembly;

	/** VLAN offload capability */
	odp_vlan_offload_capability_t vlan_offload;

	/** Statistics counters capabilities */
	odp_pktio_stats_capability_t stats;

} odp_pktio_capability_t;

/**
 * LSO profile parameters
 */
typedef struct odp_lso_profile_param_t {
	/**
	 * Segmentation protocol
	 *
	 * Selects on which protocol LSO operation performs segmentation (e.g. IP fragmentation vs.
	 * TCP segmentation). When ODP_LSO_PROTO_CUSTOM is selected, only custom field
	 * modifications are performed. The default value is ODP_LSO_PROTO_NONE. Check LSO
	 * capability for supported protocols.
	 */
	odp_lso_protocol_t lso_proto;

	/**
	 * Custom fields
	 *
	 * Set lso_proto to ODP_LSO_PROTO_CUSTOM when using custom fields. Fields are defined
	 * in the same order they appear in the packet.
	 */
	struct {
		/** Custom field to be modified by LSO */
		struct {
			/** Field modify operation. Selects how value of the field is modified
			 *  from its original value during segmentation. Field value is assumed
			 *  to be in network (big endian) byte order. */
			odp_lso_modify_t mod_op;

			/** Field offset in bytes from packet start */
			uint32_t offset;

			/** Field size in bytes. Valid values are 1, 2, 4, and 8 bytes. */
			uint8_t size;

		} field[ODP_LSO_MAX_CUSTOM];

		/** Number of custom fields specified. The default value is 0. */
		uint8_t num_custom;

	} custom;

} odp_lso_profile_param_t;

/** Link status */
typedef enum odp_pktio_link_status_t {
	ODP_PKTIO_LINK_STATUS_UNKNOWN = -1,
	ODP_PKTIO_LINK_STATUS_DOWN = 0,
	ODP_PKTIO_LINK_STATUS_UP = 1
} odp_pktio_link_status_t;

/**
 * Packet IO information
 */
typedef struct odp_pktio_info_t {
	/** Packet IO device name */
	const char       *name;

	/** Packet IO driver name (implementation specific) */
	const char       *drv_name;

	/** Packet pool */
	odp_pool_t        pool;

	/** Packet IO parameters */
	odp_pktio_param_t param;

} odp_pktio_info_t;

/** @name Link speed
 *  Packet IO link speeds in Mbps
 *  @anchor link_speed
 *  @{
 */

/** Link speed unknown */
#define	ODP_PKTIO_LINK_SPEED_UNKNOWN 0
/** Link speed 10 Mbit/s */
#define	ODP_PKTIO_LINK_SPEED_10M     10
/** Link speed 100 Mbit/s */
#define	ODP_PKTIO_LINK_SPEED_100M    100
/** Link speed 1 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_1G      1000
/** Link speed 2.5 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_2_5G    2500
/** Link speed 5 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_5G      5000
/** Link speed 10 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_10G     10000
/** Link speed 20 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_20G     20000
/** Link speed 25 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_25G     25000
/** Link speed 40 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_40G     40000
/** Link speed 50 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_50G     50000
/** Link speed 56 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_56G     56000
/** Link speed 100 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_100G    100000
/** Link speed 200 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_200G    200000
/** Link speed 400 Gbit/s */
#define	ODP_PKTIO_LINK_SPEED_400G    400000

/** @} */

/** Autonegotiation mode */
typedef enum odp_pktio_link_autoneg_t {
	/** Autonegotiation state unknown */
	ODP_PKTIO_LINK_AUTONEG_UNKNOWN = -1,
	/** Autonegotiation disabled */
	ODP_PKTIO_LINK_AUTONEG_OFF = 0,
	/** Autonegotiation enabled */
	ODP_PKTIO_LINK_AUTONEG_ON  = 1
} odp_pktio_link_autoneg_t;

/** Duplex mode */
typedef enum odp_pktio_link_duplex_t {
	ODP_PKTIO_LINK_DUPLEX_UNKNOWN = -1,
	ODP_PKTIO_LINK_DUPLEX_HALF = 0,
	ODP_PKTIO_LINK_DUPLEX_FULL = 1
} odp_pktio_link_duplex_t;

/** Ethernet pause frame (flow control) mode */
typedef enum odp_pktio_link_pause_t {
	ODP_PKTIO_LINK_PAUSE_UNKNOWN = -1,
	ODP_PKTIO_LINK_PAUSE_OFF = 0,
	ODP_PKTIO_LINK_PAUSE_ON  = 1
} odp_pktio_link_pause_t;

/**
 * Packet IO link information
 */
typedef struct odp_pktio_link_info_t {
	/** Link autonegotiation */
	odp_pktio_link_autoneg_t autoneg;
	/** Duplex mode */
	odp_pktio_link_duplex_t duplex;
	/** Link media type
	 *
	 * The implementation owned string describes link media type. Values are
	 * implementation specific short names like copper, fiber, or virtual.
	 * The value of "unknown" is used when media type cannot be determined. */
	const char *media;
	/** Reception of pause frames */
	odp_pktio_link_pause_t pause_rx;
	/** Transmission of pause frames */
	odp_pktio_link_pause_t pause_tx;
	/** Link speed in Mbps
	  *
	  * The value of zero means that the link speed is unknown.
	  * ODP_PKTIO_LINK_SPEED_* (@ref link_speed) defines can be used to
	  * compare the value to standard link speeds. */
	uint32_t speed;
	/** Link status */
	odp_pktio_link_status_t status;
} odp_pktio_link_info_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
