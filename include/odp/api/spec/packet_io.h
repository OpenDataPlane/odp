/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2020-2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_API_SPEC_PACKET_IO_H_
#define ODP_API_SPEC_PACKET_IO_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/deprecated.h>
#include <odp/api/packet_io_stats.h>
#include <odp/api/queue.h>
#include <odp/api/time.h>
#include <odp/api/packet.h>

/** @defgroup odp_packet_io ODP PACKET IO
 *  Packet IO interfaces.
 *
 * Packet IO is the Ingress and Egress interface to ODP processing. It
 * allows manipulation of the interface for setting such attributes as
 * number of queues, MAC address etc.
 * Pktio is usually followed by the classifier and a default class COS
 * can be set so that the scheduler may distribute flows. The interface
 * may be used directly in polled mode with odp_pktin_recv() and
 * odp_pktout_send().
 * Diagnostic messages can be enhanced by using odp_pktio_to_u64 which
 * will generate a printable reference for a pktio handle for use with
 * the logging.
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

	/** All bits of the bit field structure */
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
	 * parameters are ignored.
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
	unsigned int num_queues;

	/** Queue parameters
	  *
	  * These are used for input queue creation in ODP_PKTIN_MODE_QUEUE
	  * or ODP_PKTIN_MODE_SCHED modes. Scheduler parameters are considered
	  * only in ODP_PKTIN_MODE_SCHED mode. Default values are defined in
	  * odp_queue_param_t documentation.
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
	unsigned int num_queues;

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

	} bit;

	/** All bits of the bit field structure
	  *
	  * This field can be used to set/clear all flags, or bitwise
	  * operations over the entire structure. */
	uint64_t all_bits;
} odp_pktout_config_opt_t;

/**
 * Parser layers
 *
 * @deprecated Use odp_proto_layer_t instead
 */
typedef odp_proto_layer_t odp_pktio_parser_layer_t;

/** No layers
 *  @deprecated Use ODP_PROTO_LAYER_NONE, instead */
#define ODP_PKTIO_PARSER_LAYER_NONE ODP_PROTO_LAYER_NONE

/** Layer L2 protocols (Ethernet, VLAN, ARP, etc)
 *  @deprecated Use ODP_PROTO_LAYER_L2, instead */
#define ODP_PKTIO_PARSER_LAYER_L2 ODP_PROTO_LAYER_L2

/** Layer L3 protocols (IPv4, IPv6, ICMP, IPsec, etc)
 *  @deprecated Use ODP_PROTO_LAYER_L3, instead */
#define ODP_PKTIO_PARSER_LAYER_L3 ODP_PROTO_LAYER_L3

/** Layer L4 protocols (UDP, TCP, SCTP)
 *  @deprecated Use ODP_PROTO_LAYER_L4, instead */
#define ODP_PKTIO_PARSER_LAYER_L4 ODP_PROTO_LAYER_L4

/** All layers
 *  @deprecated Use ODP_PROTO_LAYER_ALL instead */
#define ODP_PKTIO_PARSER_LAYER_ALL ODP_PROTO_LAYER_ALL

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
	 * interface capability before enabling the same. */
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
	 *  LSO operation cannot be combined with IPSEC or Traffic Manager (ODP_PKTOUT_MODE_TM) on
	 *  packet output.
	 *
	 *  0: Application will not use LSO (default)
	 *  1: Application will use LSO
	 *
	 *  @see odp_pktout_send_lso()
	 */
	odp_bool_t enable_lso;

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
 * Packet IO capabilities
 */
typedef struct odp_pktio_capability_t {
	/** Maximum number of input queues */
	unsigned int max_input_queues;

	/** Maximum number of output queues */
	unsigned int max_output_queues;

	/** Supported pktio configuration options */
	odp_pktio_config_t config;

	/** Supported set operations
	 *
	 * A bit set to one indicates a supported operation. All other bits are
	 * set to zero. */
	odp_pktio_set_op_t set_op;

	/** @deprecated Use enable_loop inside odp_pktin_config_t */
	odp_bool_t ODP_DEPRECATE(loop_supported);

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

} odp_pktio_capability_t;

/**
 * Open a packet IO interface
 *
 * An ODP program can open a single packet IO interface per device, attempts
 * to open an already open device will fail, returning ODP_PKTIO_INVALID with
 * errno set. Use odp_pktio_lookup() to obtain a handle to an already open
 * device. Packet IO parameters provide interface level configuration options.
 *
 * Use odp_pktio_param_init() to initialize packet IO parameters into their
 * default values. Default values are also used when 'param' pointer is NULL.
 *
 * Packet input queue configuration must be setup with
 * odp_pktin_queue_config() before odp_pktio_start() is called. When packet
 * input mode is ODP_PKTIN_MODE_DISABLED, odp_pktin_queue_config() call is
 * optional and will ignore all parameters.
 *
 * Packet output queue configuration must be setup with
 * odp_pktout_queue_config() before odp_pktio_start() is called. When packet
 * output mode is ODP_PKTOUT_MODE_DISABLED or ODP_PKTOUT_MODE_TM,
 * odp_pktout_queue_config() call is optional and will ignore all parameters.
 *
 * Packet receive and transmit on the interface is enabled with a call to
 * odp_pktio_start(). If not specified otherwise, any interface level
 * configuration must not be changed when the interface is active (between start
 * and stop calls).
 *
 * In summary, a typical pktio interface setup sequence is ...
 *   * odp_pktio_open()
 *   * odp_pktin_queue_config()
 *   * odp_pktout_queue_config()
 *   * odp_pktio_start()
 *
 * ... and tear down sequence is:
 *   * odp_pktio_stop()
 *   * odp_pktio_close()
 *
 * @param name   Packet IO device name
 * @param pool   Default pool from which to allocate storage for packets
 *               received over this interface, must be of type ODP_POOL_PACKET
 * @param param  Packet IO parameters. Uses defaults when NULL.
 *
 * @return Packet IO handle
 * @retval ODP_PKTIO_INVALID on failure
 *
 * @note The device name "loop" is a reserved name for a loopback device used
 *	 for testing purposes.
 *
 * @note Packets arriving via this interface assigned to a CoS by the
 *	 classifier are received into the pool associated with that CoS. This
 *	 will occur either because this pktio is assigned a default CoS via
 *	 the odp_pktio_default_cos_set() routine, or because a matching PMR
 *	 assigned the packet to a specific CoS. The default pool specified
 *	 here is applicable only for those packets that are not assigned to a
 *	 more specific CoS.
 *
 * @see odp_pktio_start(), odp_pktio_stop(), odp_pktio_close()
 */
odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
			   const odp_pktio_param_t *param);

/**
 * Query packet IO interface capabilities
 *
 * Outputs packet IO interface capabilities on success.
 *
 * @param      pktio  Packet IO handle
 * @param[out] capa   Pointer to capability structure for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa);

/**
 * Maximum packet IO interface index
 *
 * Return the maximum packet IO interface index. Interface indexes
 * (e.g. returned by odp_pktio_index()) range from zero to this maximum value.
 *
 * @return Maximum packet IO interface index
 */
unsigned int odp_pktio_max_index(void);

/**
 * Configure packet IO interface options
 *
 * Select interface level configuration options before the interface is
 * activated (before odp_pktio_start() call). This step is optional in pktio
 * interface setup sequence. Use odp_pktio_capability() to query configuration
 * capabilities. Use odp_pktio_config_init() to initialize
 * configuration options into their default values. Default values are used
 * when 'config' pointer is NULL.
 *
 * @param pktio    Packet IO handle
 * @param config   Packet IO interface configuration. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_config(odp_pktio_t pktio, const odp_pktio_config_t *config);

/**
 * Configure packet input queues
 *
 * Setup a number of packet input queues and configure those. The maximum number
 * of queues is platform dependent and can be queried with
 * odp_pktio_capability(). Use odp_pktin_queue_param_init() to initialize
 * parameters into their default values. Default values are also used when
 * 'param' pointer is NULL.
 *
 * Queue handles for input queues can be requested with odp_pktin_queue() or
 * odp_pktin_event_queue() after this call. All requested queues are setup on
 * success, no queues are setup on failure. Each call reconfigures input queues
 * and may invalidate all previous queue handles.
 *
 * @param pktio    Packet IO handle
 * @param param    Packet input queue configuration parameters. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_capability(), odp_pktin_queue(), odp_pktin_event_queue()
 */
int odp_pktin_queue_config(odp_pktio_t pktio,
			   const odp_pktin_queue_param_t *param);

/**
 * Configure packet output queues
 *
 * Setup a number of packet output queues and configure those. The maximum
 * number of queues is platform dependent and can be queried with
 * odp_pktio_capability(). Use odp_pktout_queue_param_init() to initialize
 * parameters into their default values. Default values are also used when
 * 'param' pointer is NULL.
 *
 * Queue handles for output queues can be requested with odp_pktout_queue() or
 * odp_pktout_event_queue() after this call. All requested queues are setup on
 * success, no queues are setup on failure. Each call reconfigures output queues
 * and may invalidate all previous queue handles.
 *
 * @param pktio    Packet IO handle
 * @param param    Packet output queue configuration parameters. Uses defaults
 *                 when NULL.
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_capability(), odp_pktout_queue(), odp_pktout_event_queue()
 */
int odp_pktout_queue_config(odp_pktio_t pktio,
			    const odp_pktout_queue_param_t *param);

/**
 * Event queues for packet input
 *
 * Returns the number of input queues configured for the interface in
 * ODP_PKTIN_MODE_QUEUE and ODP_PKTIN_MODE_SCHED modes. Outputs up to 'num'
 * queue handles when the 'queues' array pointer is not NULL. If return value is
 * larger than 'num', there are more queues than the function was allowed to
 * output. If return value (N) is less than 'num', only queues[0 ... N-1] have
 * been written.
 *
 * Packets (and other events) from these queues are received with
 * odp_queue_deq(), odp_schedule(), etc calls.
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet input queues
 * @retval <0 on failure
 */
int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num);

/**
 * Direct packet input queues
 *
 * Returns the number of input queues configured for the interface in
 * ODP_PKTIN_MODE_DIRECT mode. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets from these queues are received with odp_pktin_recv().
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet input queues
 * @retval <0 on failure
 */
int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[], int num);

/**
 * Event queues for packet output
 *
 * Returns the number of output queues configured for the interface in
 * ODP_PKTOUT_MODE_QUEUE. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets are enqueued to these queues with odp_queue_enq() or
 * odp_queue_enq_multi(). Behaviour is undefined if other events than packets
 * are enqueued.
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet output queues
 * @retval <0 on failure
 */
int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num);

/**
 * Direct packet output queues
 *
 * Returns the number of output queues configured for the interface in
 * ODP_PKTOUT_MODE_DIRECT mode. Outputs up to 'num' queue handles when the
 * 'queues' array pointer is not NULL. If return value is larger than 'num',
 * there are more queues than the function was allowed to output. If return
 * value (N) is less than 'num', only queues[0 ... N-1] have been written.
 *
 * Packets are sent to these queues with odp_pktout_send().
 *
 * @param      pktio    Packet IO handle
 * @param[out] queues   Points to an array of queue handles for output
 * @param      num      Maximum number of queue handles to output
 *
 * @return Number of packet output queues
 * @retval <0 on failure
 */
int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[], int num);

/**
 * Start packet receive and transmit
 *
 * Activate packet receive and transmit on a previously opened or stopped
 * interface. The interface can be stopped with a call to odp_pktio_stop().
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_open(), odp_pktio_stop()
 */
int odp_pktio_start(odp_pktio_t pktio);

/**
 * Stop packet receive and transmit
 *
 * Stop packet receive and transmit on a previously started interface. New
 * packets are not received from or transmitted to the network. Packets already
 * received from the network may be still available from interface and
 * application can receive those normally. New packets may not be accepted for
 * transmit. Packets already stored for transmit are not freed. A following
 * odp_packet_start() call restarts packet receive and transmit.
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_start(), odp_pktio_close()
 */
int odp_pktio_stop(odp_pktio_t pktio);

/**
 * Close a packet IO interface
 *
 * Close a stopped packet IO interface. This call frees all remaining packets
 * stored in pktio receive and transmit side buffers. The pktio is destroyed
 * and the handle must not be used for other calls. After a successful call,
 * the same pktio device can be opened again with a odp_pktio_open() call.
 *
 * @param pktio  Packet IO handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_pktio_stop(), odp_pktio_open()
 */
int odp_pktio_close(odp_pktio_t pktio);

/**
 * Return a packet IO handle for an already open device
 *
 * @param name   Packet IO device name
 *
 * @return Packet IO handle
 * @retval ODP_PKTIO_INVALID on failure
 */
odp_pktio_t odp_pktio_lookup(const char *name);

/**
 * Receive packets directly from an interface input queue
 *
 * Receives up to 'num' packets from the pktio interface input queue. Returns
 * the number of packets received.
 *
 * When input queue parameter 'op_mode' has been set to ODP_PKTIO_OP_MT_UNSAFE,
 * the operation is optimized for single thread operation per queue and the same
 * queue must not be accessed simultaneously from multiple threads.
 *
 * @param      queue      Packet input queue handle for receiving packets
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 *
 * @return Number of packets received
 * @retval <0 on failure
 *
 * @see odp_pktin_queue()
 */
int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t packets[], int num);

/**
 * Receive packets directly from an interface input queue with timeout
 *
 * Provides the same functionality as odp_pktin_recv(), except that waits if
 * there are no packets available. Wait time is specified by the 'wait'
 * parameter.
 *
 * @param      queue      Packet input queue handle for receiving packets
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 * @param      wait       Wait time specified as as follows:
 *                        * ODP_PKTIN_NO_WAIT: Do not wait
 *                        * Other values specify the minimum time to wait.
 *                          Use odp_pktin_wait_time() to convert nanoseconds
 *                          to a valid parameter value. Wait time may be
 *                          rounded up a small, platform specific amount.
 *
 * @return Number of packets received
 * @retval <0 on failure
 */
int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[],
		       int num, uint64_t wait);

/**
 * Receive packets directly from multiple interface input queues with timeout
 *
 * Receives up to 'num' packets from one of the specified pktio interface input
 * queues. The index of the source queue is stored into 'from' output
 * parameter. If there are no packets available on any of the queues, waits for
 * packets depending on 'wait' parameter value. Returns the number of packets
 * received.
 *
 * When an input queue has been configured with 'op_mode' value
 * ODP_PKTIO_OP_MT_UNSAFE, the operation is optimized for single thread
 * operation and the same queue must not be accessed simultaneously from
 * multiple threads.
 *
 * It is implementation specific in which order the queues are checked for
 * packets. Application may improve fairness of queue service levels by
 * circulating queue handles between consecutive calls (e.g. [q0, q1, q2, q3] ->
 * [q1, q2, q3, q0] -> [q2, q3, ...).
 *
 * @param      queues[]   Packet input queue handles for receiving packets
 * @param      num_q      Number of input queues
 * @param[out] from       Pointer for output of the source queue index. Ignored
 *                        when NULL.
 * @param[out] packets[]  Packet handle array for output of received packets
 * @param      num        Maximum number of packets to receive
 * @param      wait       Wait time specified as as follows:
 *                        * ODP_PKTIN_NO_WAIT: Do not wait
 *                        * Other values specify the minimum time to wait.
 *                          Use odp_pktin_wait_time() to convert nanoseconds
 *                          to a valid parameter value. Wait time may be
 *                          rounded up a small, platform specific amount.
 *
 * @return Number of packets received
 * @retval <0 on failure
 */
int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[], unsigned int num_q,
			  unsigned int *from, odp_packet_t packets[], int num,
			  uint64_t wait);

/**
 * Packet input wait time
 *
 * Converts nanoseconds to wait time values for packet input functions.
 *
 * @param nsec   Minimum number of nanoseconds to wait
 *
 * @return Wait parameter value for packet input functions
 */
uint64_t odp_pktin_wait_time(uint64_t nsec);

/**
 * Send packets directly to an interface output queue
 *
 * Sends out a number of packets to the interface output queue. When
 * output queue parameter 'op_mode' has been set to ODP_PKTIO_OP_MT_UNSAFE,
 * the operation is optimized for single thread operation per queue and the same
 * queue must not be accessed simultaneously from multiple threads.
 *
 * A successful call returns the actual number of packets sent. If return value
 * is less than 'num', the remaining packets at the end of packets[] array
 * are not consumed, and the caller has to take care of them.
 *
 * Entire packet data is sent out (odp_packet_len() bytes of data, starting from
 * odp_packet_data()). All other packet metadata is ignored unless otherwise
 * specified e.g. for protocol offload purposes. Link protocol specific frame
 * checksum and padding are added to frames before transmission.
 *
 * @param queue        Packet output queue handle for sending packets
 * @param packets[]    Array of packets to send
 * @param num          Number of packets to send
 *
 * @return Number of packets sent
 * @retval <0 on failure
 */
int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
		    int num);

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

/**
 * Initialize LSO profile parameters
 *
 * Initialize an odp_lso_profile_param_t to its default values for all fields.
 *
 * @param param Address of the odp_lso_profile_param_t to be initialized
 */
void odp_lso_profile_param_init(odp_lso_profile_param_t *param);

/**
 * Create LSO profile
 *
 * LSO profile defines the set of segmentation operations to be performed to a packet. LSO profiles
 * are created before the packet IO interface is started (after odp_pktio_config() and before
 * odp_pktio_start()).
 *
 * See odp_lso_capability_t for maximum number of profiles supported and other LSO capabilities.
 *
 * @param pktio   Packet IO interface which is used with this LSO profile
 * @param param   LSO profile parameters
 *
 * @return LSO profile handle
 * @retval ODP_LSO_PROFILE_INVALID on failure
 */
odp_lso_profile_t odp_lso_profile_create(odp_pktio_t pktio, const odp_lso_profile_param_t *param);

/**
 * Destroy LSO profile
 *
 * LSO profiles can be destoyed only when the packet IO interface is not active (i.e. after it
 * has been stopped).
 *
 * @param lso_profile   LSO profile to be destroyed
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_lso_profile_destroy(odp_lso_profile_t lso_profile);

/**
 * Send packets with segmentation offload
 *
 * Like odp_pktout_send(), but splits a packet payload into 'max_payload_len' or smaller segments
 * during output. Packet headers (before 'payload_offset') are copied into each segment and
 * automatically modified before transmission. Header updates are based on segmentation protocol
 * selection (odp_lso_profile_param_t::lso_proto) in LSO profile. Header checksums are updated
 * after modifications. L3/L4 header modifications (see e.g. ODP_LSO_PROTO_TCP_IPV4) require that
 * L3/L4 layer offsets in the packet are valid (see e.g. odp_packet_l3_offset()).
 *
 * In addition, custom field updates may be used to cover unsupported or proprietary protocols.
 * Custom fields must not overlap with each other and can be used only when ODP_LSO_PROTO_CUSTOM
 * is selected.
 *
 * Packets are processed and transmitted in the array order. Segments of each packet are transmitted
 * in ascending order.
 *
 * When all packets share the same LSO options, usage of 'lso_opt' parameter may improve
 * performance as a number of packet metadata writes/reads are avoided. Results are undefined if
 * 'lso_opt' is NULL and a packet misses LSO options.
 *
 * Check LSO support level from packet IO capabilities (odp_pktio_capability_t).
 *
 * @param queue     Packet output queue handle
 * @param packet[]  Array of packets to be LSO processed and sent
 * @param num       Number of packets
 * @param lso_opt   When set, LSO options to be used for all packets. When NULL, LSO options are
 *                  read from each packet (see odp_packet_lso_request()).
 *
 * @return Number of packets successfully segmented (0 ... num)
 * @retval <0 on failure
 */
int odp_pktout_send_lso(odp_pktout_queue_t queue, const odp_packet_t packet[], int num,
			const odp_packet_lso_opt_t *lso_opt);

/**
 * MTU value of a packet IO interface
 *
 * @deprecated  Use odp_pktin_maxlen() and odp_pktout_maxlen() instead. MTU was
 * not well defined. There may be difference between MTU and maximum frame
 * length values.
 *
 * @param pktio  Packet IO handle.
 *
 * @return MTU value on success
 * @retval 0 on failure
 */
uint32_t ODP_DEPRECATE(odp_pktio_mtu)(odp_pktio_t pktio);

/**
 * Enable/Disable promiscuous mode on a packet IO interface.
 *
 * @param pktio   Packet IO handle.
 * @param enable  1 to enable, 0 to disable.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_pktio_promisc_mode_set(odp_pktio_t pktio, odp_bool_t enable);

/**
 * Determine if promiscuous mode is enabled for a packet IO interface.
 *
 * @param pktio  Packet IO handle.
 *
 * @retval  1 if promiscuous mode is enabled.
 * @retval  0 if promiscuous mode is disabled.
 * @retval <0 on failure
*/
int odp_pktio_promisc_mode(odp_pktio_t pktio);

/**
 * Maximum frame length at packet input
 *
 * Maximum frame length in bytes that the packet IO interface can receive.
 * For Ethernet, the frame length bytes start with MAC addresses and continue
 * to the end of the payload. So, Ethernet checksum, interpacket gap
 * and preamble bytes are excluded from the length.
 *
 * @param pktio  Packet IO handle.
 *
 * @return Maximum frame length at packet input
 * @retval 0 on failure
 */
uint32_t odp_pktin_maxlen(odp_pktio_t pktio);

/**
 * Maximum frame length at packet output
 *
 * Maximum frame length in bytes that the packet IO interface can transmit.
 * For Ethernet, the frame length bytes start with MAC addresses and continue
 * to the end of the payload. So, Ethernet checksum, interpacket gap
 * and preamble bytes are excluded from the length.
 *
 * @param pktio  Packet IO handle.
 *
 * @return Maximum frame length at packet output
 * @retval 0 on failure
 */
uint32_t odp_pktout_maxlen(odp_pktio_t pktio);

/**
 * Set maximum frame lengths
 *
 * Set the maximum frame lengths in bytes that the packet IO interface can
 * receive and transmit. For Ethernet, the frame length bytes start with MAC
 * addresses and continue to the end of the payload. So, Ethernet checksum,
 * interpacket gap, and preamble bytes are excluded from the lengths.
 *
 * Use odp_pktio_capability() to query interface capabilities. If setting
 * maximum frame length is only supported in input or output direction, the
 * parameter for the unsupported direction has to be set to zero. When
 * 'equal' flag in odp_pktio_capability_t::maxlen is set, the same maximum
 * frame length value has to be used for both input and output directions.
 *
 * @param pktio         Packet IO handle
 * @param maxlen_input  Maximum frame length at packet input
 * @param maxlen_output Maximum frame length at packet output
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @see odp_pktin_maxlen(), odp_pktout_maxlen()
 */
int odp_pktio_maxlen_set(odp_pktio_t pktio, uint32_t maxlen_input,
			 uint32_t maxlen_output);

/**
 * Get the default MAC address of a packet IO interface.
 *
 * @param	pktio     Packet IO handle
 * @param[out]	mac_addr  Output buffer (use ODP_PKTIO_MACADDR_MAXSIZE)
 * @param       size      Size of output buffer
 *
 * @return Number of bytes written (actual size of MAC address)
 * @retval <0 on failure
 */
int odp_pktio_mac_addr(odp_pktio_t pktio, void *mac_addr, int size);

/**
 * Set the default MAC address of a packet IO interface.
 *
 * Support of this operation on a packet IO interface is reported
 * through ‘mac_addr’ set operation capability.
 *
 * @param	pktio     Packet IO handle
 * @param	mac_addr  MAC address to be set as default address
 * @param	size      Size of the MAC address
 *
 * @return 0 on success
 * @retval <0 on failure
 */
int odp_pktio_mac_addr_set(odp_pktio_t pktio, const void *mac_addr,
			   int size);

/**
 * Setup per-port default class-of-service.
 *
 * @param pktio        Ingress port pktio handle.
 * @param default_cos  Class-of-service set to all packets arriving at this
 *                     ingress port, unless overridden by subsequent
 *                     header-based filters.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note The default_cos has to be unique per odp_pktio_t instance.
 */
int odp_pktio_default_cos_set(odp_pktio_t pktio, odp_cos_t default_cos);

/**
 * Setup per-port error class-of-service
 *
 * @param pktio      Ingress port pktio handle.
 * @param error_cos  class-of-service set to all packets arriving at this
 *                   ingress port that contain an error.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_pktio_error_cos_set(odp_pktio_t pktio, odp_cos_t error_cos);

/**
 * Setup per-port header offset
 *
 * @param pktio      Ingress port pktio handle.
 * @param offset     Number of bytes the classifier must skip.
 *
 * This option is input to packet input parser/classifier indicating
 * how many bytes of data should be skipped from start of packet,
 * before parsing starts. So this option effects all packet input
 * protocol identification and other offloads.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_pktio_skip_set(odp_pktio_t pktio, uint32_t offset);

/**
 * Specify per-port buffer headroom
 *
 * @param pktio     Ingress port pktio handle.
 * @param headroom  Number of bytes of space preceding packet data to reserve
 *                  for use as headroom. Must not exceed the implementation
 *                  defined ODP_PACKET_MAX_HEADROOM.
 *
 * @retval			0 on success
 * @retval			<0 on failure
 *
 * @note Optional.
 */
int odp_pktio_headroom_set(odp_pktio_t pktio, uint32_t headroom);

/**
 * Get pktio interface index
 *
 * @param pktio   Packet I/O handle
 *
 * @return        Packet interface index (0..odp_pktio_max_index())
 * @retval <0     On failure (e.g., handle not valid)
 */
int odp_pktio_index(odp_pktio_t pktio);

/**
 * Get printable value for an odp_pktio_t
 *
 * @param pktio   odp_pktio_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pktio_t handle.
 */
uint64_t odp_pktio_to_u64(odp_pktio_t pktio);

/**
 * Initialize pktio params
 *
 * Initialize an odp_pktio_param_t to its default values for all fields
 *
 * @param param Address of the odp_pktio_param_t to be initialized
 */
void odp_pktio_param_init(odp_pktio_param_t *param);

/**
 * Initialize packet input queue parameters
 *
 * Initialize an odp_pktin_queue_param_t to its default values.
 *
 * @param param   Input queue parameter structure to be initialized
 */
void odp_pktin_queue_param_init(odp_pktin_queue_param_t *param);

/**
 * Initialize packet output queue parameters
 *
 * Initialize an odp_pktout_queue_param_t to its default values.
 *
 * @param param   Output queue parameter structure to be initialized
 */
void odp_pktout_queue_param_init(odp_pktout_queue_param_t *param);

/**
 * Initialize packet IO configuration options
 *
 * Initialize an odp_pktio_config_t to its default values.
 *
 * @param config  Packet IO interface configuration
 */
void odp_pktio_config_init(odp_pktio_config_t *config);

/**
 * Print pktio info to the console
 *
 * Print implementation-defined pktio debug information to the console.
 *
 * @param pktio	                Packet IO handle
 */
void odp_pktio_print(odp_pktio_t pktio);

/** Link status */
typedef enum odp_pktio_link_status_t {
	ODP_PKTIO_LINK_STATUS_UNKNOWN = -1,
	ODP_PKTIO_LINK_STATUS_DOWN = 0,
	ODP_PKTIO_LINK_STATUS_UP = 1
} odp_pktio_link_status_t;

/**
 * Determine pktio link is up or down for a packet IO interface.
 *
 * @param pktio Packet IO handle.
 *
 * @retval  ODP_PKTIO_LINK_STATUS_UP or ODP_PKTIO_LINK_STATUS_DOWN on success
 * @retval  ODP_PKTIO_LINK_STATUS_UNKNOWN on failure
*/
odp_pktio_link_status_t odp_pktio_link_status(odp_pktio_t pktio);

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

/**
 * Retrieve information about a pktio
 *
 * Fills in packet IO information structure with current parameter values.
 * May be called any time with a valid pktio handle. The call is not
 * synchronized with configuration changing calls. The application should
 * ensure that it does not simultaneously change the configuration and retrieve
 * it with this call. The call is not intended for fast path use. The info
 * structure is written only on success.
 *
 * @param      pktio   Packet IO handle
 * @param[out] info    Pointer to packet IO info struct for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_info(odp_pktio_t pktio, odp_pktio_info_t *info);

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
 * Retrieve information about packet IO link status
 *
 * Fills in link information structure with the current link status values.
 * May be called any time with a valid pktio handle. The call is not intended
 * for fast path use. The info structure is written only on success.
 *
 * @param      pktio   Packet IO handle
 * @param[out] info    Pointer to packet IO link info struct for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_link_info(odp_pktio_t pktio, odp_pktio_link_info_t *info);

/**
 * Packet input timestamp resolution in hertz
 *
 * @deprecated Use odp_pktio_ts_res() instead, which returns resolution for
 * both packet input and output timestamps.
 *
 * This is the resolution of packet input timestamps. Returns zero on a failure
 * or when timestamping is disabled.
 *
 * @param      pktio   Packet IO handle
 *
 * @return Packet input timestamp resolution in hertz
 * @retval 0 on failure
 */
uint64_t ODP_DEPRECATE(odp_pktin_ts_res)(odp_pktio_t pktio);

/**
 * Convert nanoseconds to packet input time
 *
 * @deprecated Use odp_pktio_ts_from_ns() instead, which can be used with both
 * packet input and output timestamps.
 *
 * Packet input time source is used for timestamping incoming packets.
 * This function is used convert nanosecond time to packet input timestamp time.
 *
 * @param      pktio   Packet IO handle
 * @param      ns      Time in nanoseconds
 *
 * @return Packet input timestamp
 */
odp_time_t ODP_DEPRECATE(odp_pktin_ts_from_ns)(odp_pktio_t pktio, uint64_t ns);

/**
 * Packet IO timestamp resolution in hertz
 *
 * This is the resolution of packet input and output timestamps using a packet
 * IO time source.
 *
 * @param      pktio   Packet IO handle
 *
 * @return Packet IO timestamp resolution in hertz
 * @retval 0 on failure
 */
uint64_t odp_pktio_ts_res(odp_pktio_t pktio);

/**
 * Convert nanoseconds to packet IO time
 *
 * Packet IO time source is used for timestamping incoming and outgoing packets.
 * This function is used to convert nanosecond time to packet input or output
 * timestamp time.
 *
 * @param      pktio   Packet IO handle
 * @param      ns      Time in nanoseconds
 *
 * @return Packet IO timestamp
 * @retval ODP_TIME_NULL on failure
 */
odp_time_t odp_pktio_ts_from_ns(odp_pktio_t pktio, uint64_t ns);

/**
 * Current packet IO time and global time
 *
 * Returns current packet IO time and optionally global time. The returned
 * global time is that of global time source, where as the packet IO time is of
 * packet IO time source that is used to timestamp incoming and outgoing
 * packets.
 *
 * @param      pktio        Packet IO handle
 * @param[out] ts_global    Pointer to odp_time_t for output or NULL.
 *                          On success, global timestamp will be taken at the
 *                          same point of time as packet IO time.
 *
 * @return Current packet IO time
 * @retval ODP_TIME_NULL on failure
 */
odp_time_t odp_pktio_time(odp_pktio_t pktio, odp_time_t *ts_global);

/**
 * Read last captured Tx timestamp of a packet if available and clear it for
 * next timestamp.
 *
 * @param      pktio   Packet IO handle
 * @param[out] ts      Pointer to odp_time_t for output
 *
 * @retval  0 on success
 * @retval >0 Timestamp not available either because none has been requested or
 *            the requested timestamp is not yet available. In case it is the
 *            latter, then retry again later for retrieving the timestamp.
 * @retval <0 on failure
 */
int odp_pktout_ts_read(odp_pktio_t pktio, odp_time_t *ts);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
