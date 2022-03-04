/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * Copyright (c) 2022, Marvell
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_API_SPEC_TRAFFIC_MNGR_H_
#define ODP_API_SPEC_TRAFFIC_MNGR_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io_types.h>
#include <odp/api/std_types.h>

/**
 * @file
 *
 */

/** @defgroup odp_traffic_mngr ODP TRAFFIC MNGR
 * @{
 *
 * Traffic management on packet output.
 *
 * This file forms a simple interface for creating, configuring and using
 * Traffic Management (TM) subsystems.  By TM subsystem it is meant a general
 * packet scheduling system that accepts packets from input queues and applies
 * strict priority scheduling, weighted fair queueing scheduling and/or
 * bandwidth controls to decide which input packet should be chosen as the
 * next output packet and when this output packet can be sent onwards.
 *
 * A given platform supporting this TM API could support one or more pure
 * hardware based packet scheduling systems, one or more pure software
 * based systems or one or more hybrid systems - where because of
 * hardware constraints some of the packet scheduling is done in hardware
 * and some is done in software.  In addition, there may also be additional
 * APIs beyond those described here for (a) controlling advanced capabilities
 * supported by specific hardware, software or hybrid subsystems or (b)
 * dealing with constraints and limitations of specific implementations.
 */

/**
 * @def ODP_TM_MAX_NUM_SYSTEMS
 * The maximum number of TM systems that may be created.  On some platforms
 * this might be much more limited to as little as one hardware TM system.
 */

/**
 * @def ODP_TM_MAX_PRIORITIES
 * The largest range of priorities that any TM system can support.  All strict
 * priority values MUST in the range 0..ODP_TM_MAX_PRIORITIES-1.
 */

/**
 * @def ODP_TM_MAX_LEVELS
 * The largest range of tm_node levels that any TM system can support.  Hence
 * all tm_node level values MUST be in the range 0..ODP_TM_MAX_LEVELS-1.
 * Smaller tm_node levels are associated with tm_nodes closer to the TM system
 * egress.
 */

/**
 * @def ODP_TM_MIN_SCHED_WEIGHT
 * The smallest SCHED weight is 1 (i.e. 0 is not a legal WFQ/WRR value).
 */

/**
 * @def ODP_TM_MAX_SCHED_WEIGHT
 * The largest weight any TM system can support (at least from a configuration
 * standpoint).  A given TM system could have a smaller value.
 */

/**
 * @def ODP_TM_MAX_TM_QUEUES
 * The largest number of tm_queues that can be handled by any one TM system.
 */

/**
 * @def ODP_TM_MAX_NUM_OUTPUTS
 * The largest number of outputs that can be configured for any one TM system.
 */

/**
 * @def ODP_TM_MAX_NUM_TM_NODES
 * The largest number of tm_nodes that can be in existence for any one TM
 * system.
 */

/**
 * @def ODP_TM_MAX_TM_NODE_FANIN
 * The largest number of fan-in "inputs" that can be simultaneously connected
 * to a single tm_node.
 */

/**
 * @def ODP_TM_INVALID_PRIORITY
 * Used to indicate an invalid priority value.
 */

/**
 * @typedef odp_tm_percent_t
 * Is used when specifying fields that are percentages.  It is a fixed point
 * integer whose units are 1/100 of a percent.  Hence 100% is represented as
 * the integer value 10000.  Note that because it is often used as a ratio of
 * the current queue value and maximum queue threshold, it can be > 100%, but
 * in any event will never be larger than 500% (i.e. it MUST be capped at
 * 50000).
 */

/**
 * @typedef odp_tm_t
 * Each odp_tm_t value represents a specific TM system.  Almost all functions
 * in this API require a odp_tm_t value - either directly as a function
 * parameter or indirectly by having another ODP TM handle value as a function
 * parameter.
 */

/**
 * @typedef odp_tm_queue_t
 * Each odp_tm_queue_t value is an opaque ODP handle representing a specific
 * tm_queue within a specific TM system.
 */

/**
 * @typedef odp_tm_node_t
 * Each odp_tm_node_t value is an opaque ODP handle representing a specific
 * tm node within a specific TM system.
 */

/**
 * @typedef odp_tm_shaper_t
 * Each odp_tm_shaper_t value is an opaque ODP handle representing a specific
 * shaper profile usable across all TM systems described by this API.  A given
 * shaper profile can then be attached to any tm_queue or tm_node.
 */

/**
 * @typedef odp_tm_sched_t
 * Each odp_tm_sched_t value is an opaque ODP handle representing a specific
 * tm_node scheduler profile usable across all TM systems described by this
 * API.  A given tm_node scheduler profile can then be attached to any
 * tm_node.
 */

/**
 * @typedef odp_tm_threshold_t
 * Each odp_tm_threshold_t value is an opaque ODP handle representing a
 * specific queue threshold profile usable across all TM systems described by
 * this API.  A given queue threshold profile can then be attached to any
 * tm_queue or tm_node.
 */

/**
 * @typedef odp_tm_wred_t
 * Each odp_tm_wred_t value is an opaque ODP handle representing a specific
 * WRED profile usable across all TM systems described by this API.  A given
 * WRED profile can then be attached to any tm_queue or tm_node.
 */

/**
 * @def ODP_TM_INVALID
 * Constant that can be used with any ODP TM handle type and indicates that
 * this value does NOT represent a valid TM object.
 */

/**
 * @def ODP_TM_ROOT
 * Constant that is used to refer to the egress/root node of the TM subsystem's
 * tree/hierarchy of nodes.
 */

/**
 * TM queue specific statistics counters
 */
typedef struct odp_tm_queue_stats_t {
	/** Number of octets in successfully transmitted packets. In case of
	 *  Ethernet, packet size includes MAC header. */
	uint64_t octets;

	/** Number of successfully transmitted packets. */
	uint64_t packets;

	/** Number of packets discarded due to other reasons (e.g. aging) than
	 *  errors. */
	uint64_t discards;

	/** Number of octets in packets discarded due to other reasons (e.g.
	 *  aging) than errors. */
	uint64_t discard_octets;

	/** Number of packets with transmission errors. */
	uint64_t errors;

} odp_tm_queue_stats_t;

/**
 *  TM queue level statistics capabilities
 */
typedef struct odp_tm_queue_stats_capability_t {
	/** Supported counters */
	union {
		/** Statistics counters in a bit field structure */
		struct {
			/** @see odp_tm_queue_stats_t::octets */
			uint64_t octets          : 1;

			/** @see odp_tm_queue_stats_t::packets */
			uint64_t packets         : 1;

			/** @see odp_tm_queue_stats_t::discards */
			uint64_t discards        : 1;

			/** @see odp_tm_queue_stats_t::discard_octets */
			uint64_t discard_octets  : 1;

			/** @see odp_tm_queue_stats_t::errors */
			uint64_t errors          : 1;

		} counter;

		/** All bits of the bit field structure
		 *
		 *  This field can be used to set/clear all flags, or
		 *  for bitwise operations over the entire structure. */
		uint64_t all_counters;
	};
} odp_tm_queue_stats_capability_t;

/** Per Level Capabilities
 *
 * The odp_tm_level_capabilities_t record is used to describe the capabilities
 * that might vary based upon the tm_node level.  It is always used as
 * part of the odp_tm_capabilities record. */
typedef struct {
	/** max_num_tm_nodes specifies the maximum number of tm_nodes allowed
	 * at this level. */
	uint32_t max_num_tm_nodes;

	/** max_fanin_per_level specifies the maximum number of fan_in links
	 * to any given scheduler (whether weighted or using fair queueing or
	 * round robin) belonging to tm_nodes at this level. */
	uint32_t max_fanin_per_node;

	/** max_priority specifies the maximum number of strict priority
	 * levels used by any tm_node at this level.  Note that lower numeric
	 * values represent higher (more important or time critical)
	 * priorities. */
	uint8_t max_priority;

	/** min_weight only has significance when the weights_supported field
	 * below is true, in which case it specifies the smallest value
	 * of the weights allowed at this level. */
	uint32_t min_weight;

	/** max_weight only has significance when the weights_supported field
	 * below is true, in which case it specifies the largest value
	 * of the weights allowed at this level. */
	uint32_t max_weight;

	/** Minimum allowed value for odp_tm_shaper_params_t::commit_burst and
	 * odp_tm_shaper_params_t::peak_burst when
	 * odp_tm_shaper_params_t::packet_mode is true.
	 */
	uint32_t min_burst_packets;

	/** Maximum allowed value fand odp_tm_shaper_params_t::commit_burst and
	 * odp_tm_shaper_params_t::peak_burst when
	 * odp_tm_shaper_params_t::packet_mode is true.
	 */
	uint32_t max_burst_packets;

	/** Minimum allowed value for odp_tm_shaper_params_t::commit_rate and
	 * odp_tm_shaper_params_t::peak_rate when
	 * odp_tm_shaper_params_t::packet_mode is true.
	 */
	uint64_t min_rate_packets;

	/** Maximum allowed value for odp_tm_shaper_params_t::commit_rate and
	 * odp_tm_shaper_params_t::peak_rate when
	 * odp_tm_shaper_params_t::packet_mode is true.
	 */
	uint64_t max_rate_packets;

	/** Minimum allowed value for odp_tm_shaper_params_t::commit_burst and
	 * odp_tm_shaper_params_t::peak_burst when
	 * odp_tm_shaper_params_t::packet_mode is false.
	 */
	uint32_t min_burst;

	/** Maximum allowed value for odp_tm_shaper_params_t::commit_burst and
	 * odp_tm_shaper_params_t::peak_burst when
	 * odp_tm_shaper_params_t::packet_mode is false.
	 */
	uint32_t max_burst;

	/** Minimum allowed value for odp_tm_shaper_params_t::commit_rate and
	 * odp_tm_shaper_params_t::peak_rate when
	 * odp_tm_shaper_params_t::packet_mode is false.
	 */
	uint64_t min_rate;

	/** Maximum allowed value for odp_tm_shaper_params_t::commit_rate and
	 * odp_tm_shaper_params_t::peak_rate when
	 * odp_tm_shaper_params_t::packet_mode is false.
	 */
	uint64_t max_rate;

	/** tm_node_shaper_supported indicates that the tm_nodes at this level
	 * all support TM shaping, */
	odp_bool_t tm_node_shaper_supported;

	/** tm_node_shaper_packet_mode indicates that tm_nodes at this level
	 * support shaper in packet mode */
	odp_bool_t tm_node_shaper_packet_mode;

	/** tm_node_wred_supported indicates that the tm_nodes at this level
	 * support some form of Random Early Detection. */
	odp_bool_t tm_node_wred_supported;

	/** tm_node_dual_slope_supported indicates that the tm_nodes at this
	 * level support the dual slope WRED capability.  This field is
	 * ignored if tm_node_wred_supported above is false. */
	odp_bool_t tm_node_dual_slope_supported;

	/** fair_queuing_supported indicates that the tm_node schedulers at
	 * this level can implement WFQ or FQ scheduling disciplines
	 * (otherwise these schedulers can only implement WRR or RR
	 * algorithms. */
	odp_bool_t fair_queuing_supported;

	/** weights_supported indicates that the tm_node schedulers at this
	 * level can have their different weights for their different fanins.
	 * When true the min_weight and max_weight fields above specify
	 * the legal range of such weights. */
	odp_bool_t weights_supported;

	/** tm_node_threshold indicates that the tm_nodes at this
	 * level support threshold profiles. */
	odp_bool_t tm_node_threshold;
} odp_tm_level_capabilities_t;

/** The tm_pkt_prio_mode_t enumeration type is used to indicate different
 * modes a tm system supports with respect to assigning priority to a packet
 * and propagating it across TM system. All the nodes in a TM system can
 * function only on single mode specified at time of odp_tm_create().
 */
typedef enum odp_tm_pkt_prio_mode {
	/** Indicates Packet priority preserve mode. In this mode, a packet gets
	 * its priority based on a TM queue it gets enqueued to and then it
	 * carries the same priority along with it as long as it is in the TM
	 * system. At every TM node in the topology, that specific pkt is
	 * scheduled as per that priority.
	 */
	ODP_TM_PKT_PRIO_MODE_PRESERVE,

	/** Indicates Packet priority overwrite mode. In this mode, a packet
	 * gets a new priority every time it passes through a TM queue or a
	 * TM node. All the packets fed by a fan-in node will get the same
	 * priority and that will be valid until overwritten again by another TM
	 * node. This priority is part of the TM fan-in node parameters and is
	 * fixed at node creation time.
	 */
	ODP_TM_PKT_PRIO_MODE_OVERWRITE,

	/** Max enum of Packet priority mode */
	ODP_TM_PKT_PRIO_MODE_MAX,
} odp_tm_pkt_prio_mode_t;

/** TM Capabilities Record.
 *
 * The odp_tm_capabilities_t record type is used to describe the feature set
 * and limits of a TM system. */
typedef struct {
	/** The name is an optional name associated with a capabilities
	 * record.  This name, if present, can be used by odp_tm_find to
	 * return a TM system matching this set of capabilities. */
	char *name;

	/** max_tm_queues specifies the maximum number of tm_queues that can
	 * be in existence for this TM System. */
	uint32_t max_tm_queues;

	/** max_levels specifies that maximum number of levels of hierarchical
	 * scheduling allowed by this TM System.  This is a count of the
	 * tm_node stages and does not include tm_queues or tm_egress objects.
	 * Hence any given tm_node will have associated tm_node_level in the
	 * range 0 to max_levels - 1, where tm_node's at level 0 output's only
	 * go to egress objects and tm_nodes whose level is max_levels - 1
	 * have their fan_in only from tm_queues. */
	uint8_t max_levels;

	/** egress_fcn_supported indicates whether the tm system supports
	* egress function. It is an optional feature used to receive the
	* packet from the tm system and its performance might be limited.
	*/
	odp_bool_t egress_fcn_supported;

	/** tm_queue_shaper_supported indicates that the tm_queues support
	 * proper TM shaping.  Note that TM Shaping is NOT the same thing as
	 * Ingress Metering/Policing as specified by RFC 2697 (A Single Rate
	 * Three Color Marker) or RFC 2698 (A Two Rate Three Color Marker).
	 * These RFCs can be used for a Diffserv traffic conditioner, or
	 * other ingress policing.  They make no mention of and have no
	 * algorithms for delaying packets - which is what TM shapers are
	 * expected to do. */
	odp_bool_t tm_queue_shaper_supported;

	/** tm_queue_shaper_packet_mode indicates that tm_queues support
	 * shaper in packet mode */
	odp_bool_t tm_queue_shaper_packet_mode;

	/** tm_queue_wred_supported indicates that the tm_queues support some
	 * form of Random Early Detection. */
	odp_bool_t tm_queue_wred_supported;

	/** tm_queue_dual_slope_supported indicates that the tm_queues support
	 * the dual slope WRED capability.  This field is ignored if
	 * tm_queue_wred_supported above is false. */
	odp_bool_t tm_queue_dual_slope_supported;

	/** vlan_marking_supported indicates that this TM system supports SOME
	 * form of VLAN egress marking using the odp_tm_vlan_marking()
	 * function.  This being true does not imply that all colors and
	 * subfield values and changes are supported.  Unsupported features
	 * can be detected by the marking function returning an error code. */
	odp_bool_t vlan_marking_supported;

	/** ecn_marking_supported indicates that this TM system supports
	 * Explicit Congestion Notification egress marking by using the
	 * odp_tm_ip_ecn_marking() function.  Note that the ECN is the bottom
	 * two bits of the IPv4 TOS field or the analogous IPv6 Traffic Class
	 * (TC) field.  Note that the ecn_marking_supported boolean being
	 * true does not imply that all colors are supported. */
	odp_bool_t ecn_marking_supported;

	/** drop_prec_marking_supported indicates that this TM system supports
	 * SOME form of IPv4/IPv6 egress marking by using the
	 * odp_tm_drop_prec_marking() function.  Note that the actually field
	 * modified for IPv4 pkts is called TOS, whereas the field modified
	 * for IPv6 pkts is called Traffic Class (TC) - but they are analogous
	 * fields.  Note that the drop_prec_marking_supported boolean being true
	 * does not imply that all colors and subfield values and changes are
	 * supported.  Unsupported features can be detected by the marking
	 * function returning an error code.*/
	odp_bool_t drop_prec_marking_supported;

	/** The marking_colors_supported array is used to indicate which colors
	 * can be used for marking.  A value of FALSE means that this color
	 * should not be enabled for either vlan marking, ecn marking or
	 * drop precedence marking.  A value of TRUE means that this color is
	 * supported for at least one of (and ideally all of) vlan marking,
	 * ecn marking or drop precedence marking. */
	odp_bool_t marking_colors_supported[ODP_NUM_PACKET_COLORS];

	/** The per_level array specifies the TM system capabilities that
	 * can vary based upon the tm_node level. */
	odp_tm_level_capabilities_t per_level[ODP_TM_MAX_LEVELS];

	/** dynamic_topology_update indicates support for TM system dynamic
	 * topology update. A dynamic topology update is defined as update to
	 * a TM system topology while TM system is not in stopped state.
	 * When TRUE, application can update topology dynamically
	 * without bringing the TM system to stopped state. When FALSE,
	 * application has to call odp_tm_stop() before updating the
	 * topology and odp_tm_start() after completing the update.
	 */
	odp_bool_t dynamic_topology_update;

	/** dynamic_shaper_update indicates support for TM system's dynamic
	 * shaper profile changes. When TRUE, application can update shaper
	 * profile of a TM queue or TM node dynamically.
	 * When FALSE, it implies that TM system should be brought to
	 * stopped state before changing the shaper profile or updating
	 * the parameters of the shaper profile of any TM node or TM queue.
	 */
	odp_bool_t dynamic_shaper_update;

	/** dynamic_sched_update indicates support for TM system's dynamic
	 * sched profile changes. When TRUE, application can update sched
	 * profile of a TM queue or TM node dynamically.
	 * When FALSE, it implies that TM system should be brought to
	 * stopped state before changing the sched profile or updating
	 * the parameters of the sched profile of any TM node or TM queue.
	 */
	odp_bool_t dynamic_sched_update;

	/** dynamic_wred_update indicates support for TM system's dynamic
	 * wred profile changes. When TRUE, application can update wred
	 * profile of a TM queue or TM node dynamically.
	 * When FALSE, it implies that TM system should be brought to
	 * stopped state before changing the wred profile or updating
	 * the parameters of the wred profile of any TM node or TM queue.
	 */
	odp_bool_t dynamic_wred_update;

	/** dynamic_threshold_update indicates support for TM system's dynamic
	 * threshold profile changes. When TRUE, application can update
	 * threshold profile of a TM queue or TM node dynamically.
	 * When FALSE, it implies that TM system should be brought to
	 * stopped state before changing the threshold profile or updating
	 * the parameters of the threshold profile of any TM node or TM queue.
	 */
	odp_bool_t dynamic_threshold_update;

	/** TM queue statistics counter capabilities */
	odp_tm_queue_stats_capability_t queue_stats;

	/** tm_queue_threshold indicates support for threshold profile on a
	 * TM queue. When TRUE, users can set/clear/update threshold profile
	 * on a TM queue. When false none of it is supported.
	 */
	odp_bool_t tm_queue_threshold;

	/** tm_queue_query_flags indicates supported types of TM queue query.
	 * Types of TM queue query are same as query_flags that are passed to
	 * odp_tm_queue_query(), odp_tm_priority_query() and
	 * odp_tm_total_query(). When zero, none of the queue query API's are
	 * supported. When non-zero, only the only supported types of passed
	 * query_flags are taken into account and corresponding fields updated.
	 *
	 * @see ODP_TM_QUERY_PKT_CNT, ODP_TM_QUERY_BYTE_CNT,
	 * ODP_TM_QUERY_THRESHOLDS.
	 */
	uint32_t tm_queue_query_flags;

	/** Indicates the packet priority modes supported by TM systems on a
	 * platform. A platform can support multiple packet priority modes. The
	 * actual mode a TM system runs with is defined by
	 * odp_tm_requirements_t.
	 */
	odp_bool_t pkt_prio_modes[ODP_TM_PKT_PRIO_MODE_MAX];

	/** Maximum number of schedulers supported by a TM node at any level.
	 * A TM node contains a WFQ/WRR scheduler for each packet priority level
	 * for which the node has more than one possible input. TM topology and
	 * priority configuration must be made so that the resulting number of
	 * WFQ/WRR schedulers does not exceed this capability in any TM node.
	 *
	 * The value can vary between 0 and ODP_TM_MAX_PRIORITIES.
	 */
	uint8_t max_schedulers_per_node;
} odp_tm_capabilities_t;

/** Per Level Requirements
 *
 * The odp_tm_level_requirements_t record is used to describe the requirements
 * that might vary based upon the tm_node level.  It is always used as
 * part of the odp_tm_requirements record. The default value of all boolean
 * fields is false. */
typedef struct {
	/** max_num_tm_nodes specifies the maximum number of tm_nodes required
	 * at this level. */
	uint32_t max_num_tm_nodes;

	/** max_fanin_per_level specifies the maximum number of fan_in links
	 * to any given scheduler (whether weighted or using fair queueing or
	 * round robin) required of tm_nodes at this level. */
	uint32_t max_fanin_per_node;

	/** max_priority specifies the maximum number of strict priority
	 * levels that will be used by any tm_node at this level.  Note that
	 * lower numeric values represent higher (more important or time
	 * critical) priorities. */
	uint8_t max_priority;

	/** min_weight only has significance when the weights_supported field
	 * below is true, in which case it specifies the smallest value
	 * of the weights that will be used at this level. */
	uint32_t min_weight;

	/** max_weight only has significance when the weights_supported field
	 * below is true, in which case it specifies the largest value
	 * of the weights that will be used at this level. */
	uint32_t max_weight;

	/** tm_node_shaper_needed indicates that the tm_nodes at this level
	 * are expected to do TM shaping, */
	odp_bool_t tm_node_shaper_needed;

	/** tm_node_wred_needed indicates that the tm_nodes at this level
	 * are expected to participate in some form of Random Early
	 * Detection. */
	odp_bool_t tm_node_wred_needed;

	/** tm_node_dual_slope_needed indicates that the tm_nodes at this
	 * level are expected to use the dual slope WRED capability.  This
	 * field is ignored if tm_node_wred_needed above is false. */
	odp_bool_t tm_node_dual_slope_needed;

	/** fair_queuing_needed indicates that the tm_node schedulers at
	 * this level are expected to implement WFQ or FQ scheduling
	 * disciplines. */
	odp_bool_t fair_queuing_needed;

	/** weights_needed indicates that the tm_node schedulers at this
	 * level are expected have different weights for their different
	 * fanins.  When true the min_weight and max_weight fields above
	 * specify the used range of such weights. */
	odp_bool_t weights_needed;

	/** tm_node_threshold_needed indicates that the tm_nodes at this
	 * level may use threshold profile support */
	odp_bool_t tm_node_threshold_needed;
} odp_tm_level_requirements_t;

/** TM Requirements Record.
 *
 * The odp_tm_requirements_t record type is used to describe the minimum
 * set of features and limits to be actually used by the application.
 *
 * The default value of all boolean fields is false.
 **/
typedef struct {
	/** max_tm_queues specifies the maximum number of tm_queues that will
	 * be used for this TM System. */
	uint32_t max_tm_queues;

	/** num_levels specifies that number of levels of hierarchical
	 * scheduling that will be used.  This is a count of the tm_node
	 * stages and does not include tm_queues or tm_egress objects.
	 * The default value is 0. */
	uint8_t num_levels;

	/** tm_queue_shaper_needed indicates that the tm_queues are expected
	 * to do TM shaping. */
	odp_bool_t tm_queue_shaper_needed;

	/** tm_queue_wred_needed indicates that the tm_queues are expected
	 * to participate in some form of Random Early Detection. */
	odp_bool_t tm_queue_wred_needed;

	/** tm_queue_dual_slope_needed indicates that the tm_queues are
	 * expected to use the dual slope WRED capability.  This field is
	 * ignored if tm_queue_wred_needed above is false. */
	odp_bool_t tm_queue_dual_slope_needed;

	/** tm_queue_threshold_needed indicates that the tm_queues are
	 * expected to use threshold profile support */
	odp_bool_t tm_queue_threshold_needed;

	/** vlan_marking_needed indicates that the ODP application expects
	 * to use some form of VLAN egress marking using the
	 * odp_tm_vlan_marking() function.  See also comments for
	 * vlan_marking_supported. */
	odp_bool_t vlan_marking_needed;

	/** ecn_marking_needed indicates that the ODP application expects
	 * to use some form of IPv4 TOS or IPv6 TC field egress marking by
	 * using the odp_tm_ecn_marking() function.  See also comments for
	 * ecn_marking_supported. */
	odp_bool_t ecn_marking_needed;

	/** drop_prec_marking_needed indicates that the ODP application expects
	 * to use some form of IPv4 TOS or IPv6 TC field egress marking by
	 * using the odp_tm_drop_prec_marking() function.  See also comments for
	 * drop_prec_marking_supported. */
	odp_bool_t drop_prec_marking_needed;

	/** The marking_colors_needed array is used to indicate which colors
	 * are expected to be used for marking.  A value of FALSE means that
	 * the application will not enable this color for vlan marking,
	 * ecn marking nor drop precedence marking.  A value of TRUE means that
	 * the application expects to use this color in conjunction with one or
	 * more of the marking APIs. */
	odp_bool_t marking_colors_needed[ODP_NUM_PACKET_COLORS];

	/** Packet priority mode.
	 * TM capabilities indicate which modes are supported.
	 * The default value is ODP_TM_PKT_PRIO_MODE_PRESERVE.
	 */
	odp_tm_pkt_prio_mode_t pkt_prio_mode;

	/** The per_level array specifies the TM system requirements that
	 * can vary based upon the tm_node level. */
	odp_tm_level_requirements_t per_level[ODP_TM_MAX_LEVELS];
} odp_tm_requirements_t;

/** The odp_tm_egress_fcn_t type defines the parameter profile of the egress
 * function callback.  Using an egress function callback is just one of several
 * ways of getting packets out from an egress spigot.
 */
typedef void (*odp_tm_egress_fcn_t) (odp_packet_t odp_pkt);

/** The tm_egress_kind_e enumeration type is used to indicate the kind of
 * egress object ("spigot") associated with this TM system.  Most of these
 * kinds are optional - with ODP_TM_EGRESS_PKT_IO being the only mandatory
 * kind.  The TM_EGRESS_FN - if implemented - is useful for testing the TM
 * subsystem, and users are warned that its performance might be limited.
 */
typedef enum {
	ODP_TM_EGRESS_PKT_IO,
	ODP_TM_EGRESS_FN,
} odp_tm_egress_kind_t;

/** The odp_tm_egress_t type is used to describe that type of "egress spigot"
 * associated with this TM system.
 */
typedef struct {
	odp_tm_egress_kind_t egress_kind; /**< Union discriminator */

	/** Variant parameters for different TM outputs */
	union {
		odp_pktio_t pktio;              /**< Output to PktIO */
		odp_tm_egress_fcn_t egress_fcn; /**< Output to user func */
	};
} odp_tm_egress_t;

/** Initialize Requirements record fields to their default values.
 *
 * odp_tm_requirements_init() must be called to initialize any
 * odp_tm_requirements_t record before it is first used or assigned to.
 *
 * @param requirements  A pointer to an odp_tm_requirements_t record which
 *                      is to be initialized.
 */
void odp_tm_requirements_init(odp_tm_requirements_t *requirements);

/** Initialize Egress record.
 *
 * odp_tm_egress_init() must be called to initialize any odp_tm_egress_t
 * record before it is first used or assigned to.
 *
 * @param egress  A pointer to an odp_tm_egress_t record which
 *                is to be initialized.
 */
void odp_tm_egress_init(odp_tm_egress_t *egress);

/** Query All TM Capabilities
 *
 * @deprecated Use odp_tm_egress_capabilities() instead that also additionally
 * takes egress as input to provide capabilities specific to a given egress.
 *
 * This function returns the set of TM capabilities that are common for all
 * egresses. The reason that this returns a SET of capabilities and not just
 * one, is because it is expected that many HW based implementations may have
 * one set of limits for the HW and also support a SW TM implementation with a
 * (presumably larger) different set of limits. There are also cases where
 * there could be more than one SW implementation (one supporting say tens of
 * thousands of tm_queues and a variant supporting tens of millions of
 * tm_queues). It returns capabilities that are valid for all egresses.
 * The caller passes in an array of odp_tm_capabilities_t records and the
 * maximum number of such records to output. If number of such records
 * implementation supports is larger than caller requested number, then
 * only caller requested number of records are written and return value is
 * max number of records implementation supports.
 * Caller then may again call with larger number of records to be returned.
 *
 * @param[out] capabilities      An array of odp_tm_capabilities_t records to
 *                               be filled in.
 * @param      capabilities_size The number of odp_tm_capabilities_t records
 *                               in the capabilities array.
 * @return                       Returns < 0 upon failure.  Returns N > 0,
 *                               where N is the maximum number of different
 *                               odp_tm_capabilities_t records that the
 *                               implementations supports. *NOTE* that this
 *                               number can be > capabilities_size!
 */
int ODP_DEPRECATE(odp_tm_capabilities)(odp_tm_capabilities_t capabilities[],
				       uint32_t              capabilities_size);

/** Query TM Capabilities specific to an egress
 *
 * The function returns the set of TM limits supported by this implementation
 * for a given egress. Unlike odp_tm_capability() which return's capabilities
 * of already created TM system which are limited by its requirements, this
 * function returns maximum TM system limits.
 *
 * Lack of TM support in the given egress does not cause this
 * function to return a failure. Lack of TM support is indicated
 * by zero max_tm_queues capability.
 *
 * If the pktio of an egress of the pktio kind has not been opened
 * in the ODP_PKTOUT_MODE_TM pktout mode, the capabilities will
 * indicate that TM is not supported.
 *
 * @param[out] capabilities      odp_tm_capabilities_t record to be filled in.
 * @param      egress            Only capabilities compatible with this egress
 *                               are returned.
 * @retval 0  on success
 * @retval <0 on failure
 */
int odp_tm_egress_capabilities(odp_tm_capabilities_t *capabilities,
			       const odp_tm_egress_t *egress);

/** Create/instantiate a TM Packet Scheduling system.
 *
 * @param name          The name to be assigned to this TM system.  Cannot
 *                      be NULL, and also must be unique amongst all other
 *                      TM system names.
 * @param requirements  The minimum required feature set and limits needed
 *                      by the ODP application.
 * @param egress        Describes the single egress "spigot" of this
 *                      TM system.
 * @return              Returns ODP_TM_INVALID upon failure, otherwise the
 *                      newly created TM system's odp_tm_t handle is
 *                      returned.
 */
odp_tm_t odp_tm_create(const char            *name,
		       odp_tm_requirements_t *requirements,
		       odp_tm_egress_t       *egress);

/** Find a pre-existing TM system.
 *
 * The  odp_tm_find() function can be
 * used either to find a TM system created previously with odp_tm_create OR
 * get the odp_tm_t of a built-in TM system - usually based on HW. In this
 * later case the format of the name used to refer to a specific built-in
 * hardware TM system may be platform dependent, but in any case a name of
 * "HW_TM_%u" where the number starts at 1, can be used to find a built-in
 * system independently of the best requirements match.  If name is NULL then
 * the existing (built-in or created by odp_tm_create) TM system that best
 * matches the requirements is returned.
 *
 * @param name          If NULL then only uses the requirements parameter to
 *                      find a closest match, otherwise if the name is
 *                      matched by an existing TM system it is returned.
 * @param requirements  Used when the name is NULL (in which case the
 *                      closest match is returned) or when the name is
 *                      not-NULL, but doesn't match any existing TM system
 *                      in which case the requirements is used to find the
 *                      FIRST TM system matching exactly these limits.
 * @param egress        If a TM system is found, then this specifies the
 *                      egress "spigot" to be associated with this TM
 *                      system.
 * @return              If an existing TM system (built-in or previously
 *                      created via odp_tm_create) is found, its
 *                      odp_tm_t value is returned, otherwise
 *                      ODP_TM_INVALID is returned.
 */
odp_tm_t odp_tm_find(const char            *name,
		     odp_tm_requirements_t *requirements,
		     odp_tm_egress_t       *egress);

/** Query Specific TM Capabilities
 *
 * The odp_tm_capability() function can be used to obtain the actual limits
 * of the given TM system - that was either previous "found" or "created".
 * Note that it is IMPORTANT to understand that the capabilities filled in
 * here probably will NOT match any of the "complete set" of capabilities as
 * returned by odp_tm_capabilities.  This is because the capabilities here
 * reflect the given requirements passed in.  Hence these capabilities MAY
 * (but are not always required to) contain reduced limits and features
 * based upon the actual requirements as determined by the ODP application.
 * In addition, ODP TM implementations should fail API requests that "exceed"
 * the limits or features contracted for in the requirements.
 *
 * @param tm                 TM handle
 * @param[out] capabilities  A pointer to an odp_tm_capabilities_t record
 *                           where the actual limits used by the TM system are
 *                           copied into.  Note that these limits do NOT
 *                           have to match the capability passed in if
 *                           a TM system was created by odp_tm_create,
 *                           but of course these limits in some cases could
 *                           be larger.
 *
 * @return                   Returns 0 upon success, < 0 upon failure (which
 *                           indicates that the odp_tm value did not exist).
 */
int odp_tm_capability(odp_tm_t tm, odp_tm_capabilities_t *capabilities);

/**
 * Start a TM system
 *
 * odp_tm_start() needs to be used to start an already created or found TM
 * system. By default, all the TM systems are in stopped state.
 *
 * @param tm  TM handle
 *
 * @retval 0  on success
 * @retval <0 on failure
 */
int odp_tm_start(odp_tm_t tm);

/**
 * Stop a TM system
 *
 * odp_tm_stop() can to used to stop a TM system that is already started for the
 * purpose of reconfiguration that cannot be done dynamically.
 *
 * When TM is in the stopped state,
 * - New packets must not be sent to the TM either directly by TM API or indirectly
 *   via IPsec outbound inline API. New packets can only be enqueued after
 *   starting the TM system using odp_tm_start().
 * - Packets already inflight inside TM or IPSec for transmit may get silently dropped
 *   or may get transmitted with unspecified TM treatment.
 *
 * A following call to odp_tm_start() restarts TM system and its scheduling/shaping
 * on existing and new packets.
 *
 * @param tm  TM handle
 *
 * @retval 0  on success
 * @retval <0 on failure
 *
 * @see odp_tm_capabilities_t::dynamic_topology_update
 * @see odp_tm_capabilities_t::dynamic_shaper_update
 * @see odp_tm_capabilities_t::dynamic_sched_update
 * @see odp_tm_capabilities_t::dynamic_wred_update
 * @see odp_tm_capabilities_t::dynamic_threshold_update
 */
int odp_tm_stop(odp_tm_t tm);

/** Destroy a TM system.
 *
 * odp_tm_destroy() may be used to destroy TM systems created via
 * odp_tm_create().  It generally CANNOT be used to destroy built-in TM
 * systems.  Also some platforms MAY not support destroying of TM systems
 * created via odp_tm_create() under certain conditions.  For example a given
 * platform may require that the TM system be first "drained" of all of its
 * queued packets before it will accept a odp_tm_destroy() call.
 *
 * In general calling odp_tm_destroy() on an active TM system does not
 * guarantee anything about the disposition of any packets queued within the
 * TM system, other than EVENTUALLY these packets will be either sent (in ANY
 * order) or freed.
 *
 * @param tm      The handle of the TM system to be destroyed (and hence freed).
 *
 * @return        0 upon success, < 0 upon failure.
 */
int odp_tm_destroy(odp_tm_t tm);

/* Marking APIs
 * -------------------------------------------------------- */

/** Vlan Marking.
 *
 * The odp_tm_vlan_marking() function allows one to configure the TM egress
 * so as to have it set the one bit VLAN Drop Eligibility Indicator (DEI)
 * field (but only for pkts that already carry a VLAN tag) of a pkt based upon
 * the final pkt color assigned to the pkt when it reaches the egress node. When
 * drop_eligible_enabled is false, then the given color has no effect on the
 * VLAN fields. See IEEE 802.1q for more details.
 *
 * Note that ALL ODP implementations are required to SUCCESSFULLY handle all
 * calls to this function with drop_eligible_enabled == FALSE - i.e. must
 * always return 0 when disabling this feature.
 *
 * @param tm                     Handle of the TM system whose egress behavior
 *                               is being changed.
 * @param color                  The packet color whose egress marking is
 *                               being changed.
 * @param drop_eligible_enabled  If true then will set the DEI bit for
 *                               egressed VLAN tagged pkts with this color.
 *
 * @return                       0 upon success, < 0 upon failure.
 */
int odp_tm_vlan_marking(odp_tm_t           tm,
			odp_packet_color_t color,
			odp_bool_t         drop_eligible_enabled);

/** Explicit Congestion Notification Marking.
 *
 * The odp_tm_ecn_marking() function allows one to configure the TM
 * egress so that the two bit ECN subfield of the eight bit TOS field of an
 * IPv4 pkt OR the eight bit Traffic Class (TC) field of an IPv6 pkt can be
 * selectively modified based upon the final color assigned to the pkt when it
 * reaches the egress.  Note that the IPv4 header checksum will be updated -
 * but only if the IPv4 TOS field actually changes as a result of this
 * setting or the odp_tm_drop_prec_marking setting.  For IPv6, since there is
 * no header checksum, nothing needs to be done.  Note that this marking API
 * will only ever cause both ECN bits to be set to 1 - but only for TCP pkts
 * whose incoming ECN bits are not both 0.  See RFC 3168 for more details.
 *
 * Note that ALL ODP implementations are required to SUCCESSFULLY handle all
 * calls to this function with ecn_ce_enabled == FALSE - i.e. must always
 * return 0 when disabling this feature.
 *
 * @param tm              Handle of the TM system whose egress behavior is being
 *                        changed.
 * @param color           The packet color whose egress marking is
 *                        being changed.
 * @param ecn_ce_enabled  If true then egressed IPv4/IPv6 pkts whose
 *                        protocol field is TCP AND whose ECN subfield has
 *                        either one of the two values 1 or 2, will set this
 *                        subfield to the value ECN_CE - i.e. Congestion
 *                        Experienced (whose value is 3).
 *
 * @return                0 upon success, < 0 upon failure.
 */
int odp_tm_ecn_marking(odp_tm_t           tm,
		       odp_packet_color_t color,
		       odp_bool_t         ecn_ce_enabled);

/** Drop Precedence Marking.
 *
 * The odp_tm_drop_prec_marking() function allows one to configure the TM
 * egress so that the two RFC 2597 Drop Precedence bits can be modified
 * based upon the final color assigned to the pkt when it reaches the egress.
 * The Drop Precedence bits are contained within the six bit Differentiated
 * Services Code Point subfield of the IPv4 TOS field or the IPv6 Traffic
 * Class (TC) field.  Specifically the Drop Precedence sub-subfield can be
 * accessed with a DSCP bit mask of 0x06.  When enabled for a given color,
 * these two bits will be set to Medium Drop Precedence (value 0x4) if the
 * color is ODP_PACKET_YELLOW, set to High Drop Precedence (value 0x6) if
 * the color is ODP_PACKET_RED, otherwise set to Low Drop Precedence for any
 * other color.  Of course an implementation can restrict the set of colors
 * which can be enabled via the marking_colors_supported array in the
 * odp_tm_capabilities_t record.
 *
 * Note that the IPv4 header checksum will be updated - but only if the
 * IPv4 TOS field actually changes as a result of this setting or the
 * odp_tm_ecn_marking setting.  For IPv6, since there is no header checksum,
 * nothing else needs to be done.
 *
 * Note that ALL ODP implementations are required to SUCCESSFULLY handle all
 * calls to this function with drop_prec_enabled == FALSE - i.e. must always
 * return 0 when disabling this feature.
 *
 * @param tm                Handle of the TM system whose egress behavior is
 *                          being changed.
 * @param color             The packet color whose egress marking is
 *                          being changed.
 * @param drop_prec_enabled If true then egressed IPv4/IPv6 pkts with this
 *                          color will have the pkt's Drop Precedence
 *                          sub-subfield of the DSCP subfield set to
 *                          LOW, MEDIUM or HIGH drop precedence.
 *
 * @return                  0 upon success, < 0 upon failure.
 */
int odp_tm_drop_prec_marking(odp_tm_t           tm,
			     odp_packet_color_t color,
			     odp_bool_t         drop_prec_enabled);

/* Shaper profile types and functions
 * -------------------------------------------------------- */

/**
 * TM shaper parameters
 *
 * Use odp_tm_shaper_params_init() to initialize parameters into their default
 * values.
 */
typedef struct {
	/** The committed information rate for this shaper profile.  The units
	 * for this integer is in bits per second when packet_mode is
	 * not TRUE while packets per second when packet mode is TRUE.
	 */
	union {
		/**< @deprecated Use commit_rate instead */
		uint64_t ODP_DEPRECATE(commit_bps);
		uint64_t commit_rate; /**< Commit information rate */
	};

	/** The peak information rate for this shaper profile.  The units for
	 * this integer is in bits per second when packet_mode is
	 * not TRUE while in packets per second when packet mode is TRUE.
	 * This field is ignored when dual_rate is FALSE.
	 */
	union {
		/**< @deprecated Use peak_rate instead */
		uint64_t ODP_DEPRECATE(peak_bps);
		uint64_t peak_rate; /**< Peak information rate */
	};

	/** The commit burst tolerance for this shaper profile.  The units for
	 * this field is bits when packet_mode is not TRUE and packets when
	 * packet_mode is TRUE.  This value sets an upper limit for the
	 * size of the commitCnt. */
	uint32_t commit_burst;

	/** The peak burst tolerance for this shaper profile.  The units for
	 * this field in bits when packet_mode is not TRUE and packets
	 * when packet_mode is TRUE. This value sets an upper limit for the
	 * size of the peakCnt.
	 * This field is ignored when dual_rate is FALSE.
	 */
	uint32_t peak_burst;

	/** The shaper_len_adjust is a value between -128 and 127 which is
	 * directly added to the frame_len of a packet associated with this
	 * profile.  The frame_len would normally include the outermost
	 * Ethernet header (DA, SA, ...) through to the outermost Ethernet CRC
	 * inclusive.  Hence this field - when non-zero - will usually be set
	 * to a value approximating the "time" (in units of bytes) taken by
	 * the Ethernet preamble and Inter Frame Gap.  Traditionally this
	 * would be the value 20 (8 + 12), but in same cases can be as low as
	 * 9 (4 + 5).
	 * This field is ignored when packet_mode is TRUE.
	 *
	 * The default value is 0. */
	int8_t shaper_len_adjust;

	/** If dual_rate is TRUE it indicates the desire for the
	 * implementation to use dual rate shaping for packets associated with
	 * this profile.  The precise semantics of dual rate shaping are
	 * implementation specific, but in any case require a non-zero set of
	 * both commit and peak parameters.
	 *
	 * The default value is false. */
	odp_bool_t dual_rate;

	/** If packet_mode is TRUE it indicates that shaper should work
	 * in packet mode ignoring lengths of packet and hence shaping
	 * traffic in packet's per second as opposed to bits per second.
	 *
	 * The default value is false. */
	odp_bool_t packet_mode;
} odp_tm_shaper_params_t;

/**
 * Initialize TM shaper parameters
 *
 * Initialize an odp_tm_shaper_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_shaper_params_t to be initialized
 */
void odp_tm_shaper_params_init(odp_tm_shaper_params_t *params);

/** odp_tm_shaper_create() creates a shaper profile object, which can
 * subsequently be attached to any number (including zero) of tm_queues
 * or tm_nodes.
 *
 * @param name    Optional name associated with this shaper profile.  Can
 *                be NULL.  If non-NULL must be unique amongst the set of
 *                all other shaper profiles.
 * @param params  The profile parameters.  See comments associated with
 *                the odp_tm_shaper_params_t for more details.
 * @return        Returns ODP_TM_INVALID upon failure, or the newly
 *                allocated odp_tm_shaper_t value representing this
 *                profile object.
 */
odp_tm_shaper_t odp_tm_shaper_create(const char *name,
				     const odp_tm_shaper_params_t *params);

/** Destroy shaper profile object
 *
 * The odp_tm_shaper_destroy() function destroys/frees the given shaper
 * profile object.  It is an error if this shaper profile is still being
 * referenced by an active (connected) tm_node.
 *
 * @param shaper_profile   Specifies the shaper profile object which is
 *                         being destroyed.
 * @return                 Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_shaper_destroy(odp_tm_shaper_t shaper_profile);

/** odp_tm_shaper_params_read() "gets" the current set of values associated
 * with the specified shaper profile object, and copies them into the supplied
 * record.
 *
 * @param      shaper_profile  Specifies the shaper profile object whose
 *                             values are to be read.
 * @param[out] params          A pointer to an odp_tm_shaper_params_t record
 *                             where the current shaper profile object values
 *                             are copied to.
 * @return                     Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_shaper_params_read(odp_tm_shaper_t shaper_profile,
			      odp_tm_shaper_params_t *params);

/** odp_tm_shaper_params_update() "sets" the current set of values associated
 * with the specified shaper profile object.  In addition, this call has the
 * effect that all tm_input's and tm_nodes that are associated (attached?)
 * with this shaper profile object will be updated with the new values.
 *
 * @param shaper_profile  Specifies the shaper profile object whose
 *                        values are to be set.
 * @param params          A pointer to an odp_tm_shaper_params_t record
 *                        where the new shaper profile object values
 *                        are taken from.
 * @return                Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_shaper_params_update(odp_tm_shaper_t shaper_profile,
				const odp_tm_shaper_params_t *params);

/** odp_tm_shaper_lookup() can be used to find the shaper profile object
 * created with the specified name.
 *
 * @param name  Name of a previously created shaper profile.  Cannot be NULL.
 *
 * @return      Returns ODP_TM_INVALID upon failure, or the shaper
 *              profile handle created with this name.
 */
odp_tm_shaper_t odp_tm_shaper_lookup(const char *name);

/* Scheduler Profiles - types and functions
 * -------------------------------------------------------- */

/** The odp_tm_sched_mode_t type is used to control whether a tm_node
 * scheduler takes into account packet lengths (by setting the sched_mode to
 * ODP_TM_BYTE_BASED_WEIGHTS) or instead treat packets with different lengths
 * the same (by setting the sched_mode to ODP_TM_FRAME_BASED_WEIGHTS).
 * Normally the sched_mode will be set to ODP_TM_BYTE_BASED_WEIGHTS, otherwise
 * the scheduler becomes a weighted round robin scheduler.
 */
typedef enum {
	ODP_TM_BYTE_BASED_WEIGHTS, /**< Use the packet length in
				      scheduler algorithm */
	ODP_TM_FRAME_BASED_WEIGHTS /**< Ignore the packet length */
} odp_tm_sched_mode_t;

/**
 * TM scheduler parameters
 *
 * Use odp_tm_sched_params_init() to initialize parameters into their default
 * values.
 */
typedef struct {
	/** sched_modes indicates whether weighted scheduling should be used
	 * or not - on a priority basis.
	 * The default value is ODP_TM_BYTE_BASED_WEIGHTS for all priorities */
	odp_tm_sched_mode_t sched_modes[ODP_TM_MAX_PRIORITIES];

	/** In the case that sched_modes for a given strict priority level
	 * indicates the use of weighted scheduling, this field supplies the
	 * weighting factors.  The weights - when defined - are used such that
	 * the (adjusted) frame lengths are divided by these weights
	 * (i.e. they are divisors and not multipliers).  Consequently a
	 * weight of 0 (when sched_mode is ODP_TM_BYTE_BASED_WEIGHTS) is
	 * illegal. */
	uint32_t sched_weights[ODP_TM_MAX_PRIORITIES];
} odp_tm_sched_params_t;

/**
 * Initialize TM scheduler parameters
 *
 * Initialize an odp_tm_sched_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_sched_params_t to be initialized
 */
void odp_tm_sched_params_init(odp_tm_sched_params_t *params);

/** odp_tm_sched_create() creates a scheduler profile object, which can
 * subsequently be attached to any number (including zero) of tm_nodes.
 *
 * @param name    Optional name associated with this scheduler profile.
 *                Can be NULL.  If non-NULL must be unique amongst the
 *                set of all other scheduler profiles.
 * @param params  The profile parameters.  See comments associated with
 *                the odp_tm_sched_params_t for more details.
 * @return        Returns ODP_TM_INVALID upon failure, or the newly
 *                allocated odp_tm_sched_t value representing this profile
 *                object.
 */
odp_tm_sched_t odp_tm_sched_create(const char *name,
				   const odp_tm_sched_params_t *params);

/** Destroy scheduler profile object
 *
 * The odp_tm_sched_destroy() function destroys/frees the given scheduler
 * profile object.  It is an error if this scheduler profile is still being
 * referenced by an active (connected) tm_node.
 *
 * @param sched_profile  Specifies the shaper profile object which is
 *                       being destroyed.
 * @return               Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_sched_destroy(odp_tm_sched_t sched_profile);

/** odp_tm_sched_params_read() "gets" the current set of values associated
 * with the specified scheduler profile object, and copies them into the
 * supplied record.
 *
 * @param      sched_profile  Specifies the scheduler profile whose values
 *                            are to be read.
 * @param[out] params         A pointer to an odp_tm_sched_params_t record
 *                            where the current scheduler profile object
 *                            values are copied to.
 * @return                    Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_sched_params_read(odp_tm_sched_t sched_profile,
			     odp_tm_sched_params_t *params);

/** odp_tm_sched_params_update() "sets" the current set of values associated
 * with the specified scheduler profile object.  In addition, this call has
 * the effect that all tm_nodes that are associated (attached?) with this
 * Scheduler profile object will be updated with the new values.
 *
 * @param sched_profile   Specifies the Scheduler profile object whose
 *                        values are to be set.
 * @param params          A pointer to an odp_tm_sched_params_t record
 *                        where the new scheduler profile object values
 *                        are taken from.
 * @return                Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_sched_params_update(odp_tm_sched_t sched_profile,
			       const odp_tm_sched_params_t *params);

/** odp_tm_sched_lookup() can be used to find the scheduler profile object
 * created with the specified name.
 *
 * @param name  Name of a previously created scheduler profile.  Cannot be NULL.
 *
 * @return      Returns ODP_TM_INVALID upon failure, or the scheduler
 *              profile handle created with this name.
 */
odp_tm_sched_t odp_tm_sched_lookup(const char *name);

/* Queue Threshold Profiles - types and functions
 * -------------------------------------------------------- */

/**
 * TM threshold parameters
 *
 * Use odp_tm_threshold_params_init() to initialize parameters into their
 * default values.
 */
typedef struct {
	uint64_t max_pkts; /**<  max pkt cnt for this threshold profile */
	uint64_t max_bytes; /**<  max byte cnt for this threshold profile */

	/** TRUE if max_pkts is valid. The default value is false. */
	odp_bool_t enable_max_pkts;

	/** TRUE if max_bytes is valid. The default value is false. */
	odp_bool_t enable_max_bytes;
} odp_tm_threshold_params_t;

/**
 * Initialize TM threshold parameters
 *
 * Initialize an odp_tm_threshold_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_threshold_params_t to be initialized
 */
void odp_tm_threshold_params_init(odp_tm_threshold_params_t *params);

/** odp_tm_threshold_create() creates a queue threshold profile object, which
 * can subsequently be attached to any number (including zero) of tm_queues or
 * tm_nodes.
 *
 * @param name    Optional name associated with this queue threshold
 *                profile.  Can be NULL.  If non-NULL must be unique
 *                amongst the set of all other queue threshold profiles.
 * @param params  The profile parameters.  See comments associated with
 *                the odp_tm_threshold_params_t for more details.
 * @return        Returns ODP_TM_INVALID upon failure, or the newly
 *                allocated odp_tm_threshold_t value representing this
 *                profile object.
 */
odp_tm_threshold_t odp_tm_threshold_create(const char *name,
					   const odp_tm_threshold_params_t
					   *params);

/** Destroy a queue threshold profile object
 *
 * The odp_tm_threshold_destroy() function destroys/frees the given threshold
 * profile object.  It is an error if this threshold profile is still being
 * referenced by an active (connected) tm_queue or tm_node.
 *
 * @param threshold_profile  Specifies the queue thresholds profile
 *                           object which is being destroyed.
 * @return                   Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_threshold_destroy(odp_tm_threshold_t threshold_profile);

/** odp_tm_thresholds_params_read() "gets" the current set of values associated
 * with the specified queue thresholds profile object, and copies them into the
 * supplied record.
 *
 * @param      threshold_profile  Specifies the queue thresholds profile
 *                                object whose values are to be read.
 * @param[out] params             A pointer to an odp_tm_threshold_params_t
 *                                record where the current queue thresholds
 *                                profile object values are copied to.
 * @return                        Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_thresholds_params_read(odp_tm_threshold_t threshold_profile,
				  odp_tm_threshold_params_t *params);

/** odp_tm_thresholds_params_update() "sets" the current set of values
 * associated with the specified queue thresholds profile object.  In addition,
 * this call has the effect that all tm_input's and tm_nodes that are
 * associated (attached?) with this queue thresholds profile object will be
 * updated with the new values.
 *
 * @param threshold_profile  Specifies the queue thresholds profile
 *                           object whose values are to be set.
 * @param params             A pointer to an odp_tm_threshold_params_t
 *                           record where the current queue thresholds
 *                           profile object values are taken from.
 * @return                   Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_thresholds_params_update(odp_tm_threshold_t threshold_profile,
				    const odp_tm_threshold_params_t *params);

/** odp_tm_thresholds_lookup() can be used to find the queue thresholds
 * profile object created with the specified name.
 *
 * @param name  Name of a previously created queue thresholds profile.
 *              Cannot be NULL.
 * @return      Returns ODP_TM_INVALID upon failure, or the queue
 *              thresholds profile handle created with this name.
 */
odp_tm_threshold_t odp_tm_thresholds_lookup(const char *name);

/* WRED Profiles - types and functions
 * -------------------------------------------------------- */

/**
 * TM WRED parameters
 *
 * Use odp_tm_wred_params_init() to initialize parameters into their default
 * values.
 */
typedef struct {
	/** When min_threshold is set to zero then single-slope WRED is
	 * enabled, as described in the description of med_threshold.
	 * Otherwise dual-slope WRED is enabled whereby the behavior depends
	 * on which of the following three cases exists:
	 * <ol> <li> queue
	 * fullness < min_threshold.  In this case the drop probability is
	 * zero.
	 * <li> min_threshold <= queue fullness < med_threshold.  In
	 * this case the drop probability increases linearly from zero until
	 * it reaches med_drop_prob at a queue fullness equal to
	 * med_threshold.
	 * <li> med_threshold <= queue fullness.  In this case
	 * the drop probability increases linearly from med_drop_prob when the
	 * queue fullness equals med_threshold until it reaches 100% with a
	 * drop probability of max_drop_prob.  </ol> */
	odp_tm_percent_t min_threshold;

	/** The meaning of med_threshold depends upon whether single-slope or
	 * dual-slope WRED is being used or not.  When min_threshold is 0 then
	 * single-slope WRED is enabled in which case the med_threshold value
	 * represents (as a percentage of max queue fullness) the point at
	 * which the drop probability starts increasing linearly from 0 until
	 * it becomes equal to max_drop_prob when the queue fullness reaches
	 * 100%.  See min_threshold comments for the case of dual-slope WRED. */
	odp_tm_percent_t med_threshold;

	/** The med_drop_prob is only used when dual-slope WRED is being used,
	 * in which case med_drop_prob MUST be < max_drop_prob.  See
	 * min_threshold comments for more details. */
	odp_tm_percent_t med_drop_prob;

	/** The max_drop_prob equals the drop probability when the queue
	 * fullness almost equals 100%.  Of course once the queue fullness is
	 * >= 100% of the max queue fullness, the drop probability
	 * discontinuously becomes 100%. */
	odp_tm_percent_t max_drop_prob;

	/** When enable_wred is false, all tm_queues and tm_nodes that are
	 * attached to this profile will not take part in a Random Early
	 * Detection algorithm. The default value is false. */
	odp_bool_t enable_wred;

	/** When use_byte_fullness is true then WRED will use queue memory
	 * usage as the fullness criterion, otherwise when use_byte_fullness
	 * is false, WRED will use the queue length (i.e. the number of
	 * packets in the queue) as the fullness criterion.  Often will be set
	 * to true for WRED profiles applied to tm_queues and set to false for
	 * WRED profiles applied to tm_nodes. The default value is false. */
	odp_bool_t use_byte_fullness;
} odp_tm_wred_params_t;

/**
 * Initialize TM WRED parameters
 *
 * Initialize an odp_tm_wred_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_wred_params_t to be initialized
 */
void odp_tm_wred_params_init(odp_tm_wred_params_t *params);

/** odp_tm_wred_create() creates a WRED (Weighted Random Early Detection)
 * profile object, which can subsequently be attached to any number (including
 * zero) of tm_queues or tm_nodes.
 *
 * @param name    Optional name associated with this WRED profile.  Can
 *                be NULL.  If non-NULL must be unique amongst the set of
 *                all other WRED profiles.
 * @param params  The profile parameters.  See comments associated with the
 *                odp_tm_wred_params_t for more details.
 * @return        Returns ODP_TM_INVALID upon failure, or the newly
 *                allocated odp_tm_wred_t value representing this profile
 *                object.
 */
odp_tm_wred_t odp_tm_wred_create(const char *name,
				 const odp_tm_wred_params_t *params);

/** Destroy WRED profile object
 *
 * The odp_tm_wred_destroy() function destroys/frees the given WRED
 * profile object.  It is an error if this profile object is still being
 * referenced by an active (connected) tm_node.
 *
 * @param wred_profile   Specifies the WRED profile object which is
 *                       being destroyed.
 * @return               Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_wred_destroy(odp_tm_wred_t wred_profile);

/** odp_tm_wred_params_read() "gets" the current set of values associated
 * with the specified WRED profile object, and copies them into the supplied
 * record.
 *
 * @param      wred_profile  Specifies the WRED profile object whose
 *                           values are to be read.
 * @param[out] params        A pointer to an odp_tm_wred_params_t record
 *                           where the current WRED profile object values
 *                           are copied to.
 * @return                   Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_wred_params_read(odp_tm_wred_t wred_profile,
			    odp_tm_wred_params_t *params);

/** odp_tm_wred_params_update() "sets" the current set of values associated
 * with the specified WRED profile object.  In addition, this call has the
 * effect that all tm_input's and tm_nodes that are associated (attached?)
 * with this WRED profile object will be updated with the new values.
 *
 * @param wred_profile  Specifies the WRED profile object whose
 *                      values are to be set.
 * @param params        A pointer to an odp_tm_wred_params_t record
 *                      where the new WRED profile object values
 *                      are taken from.
 * @return              Returns < 0 upon failure or 0 upon success.
 */
int odp_tm_wred_params_update(odp_tm_wred_t wred_profile,
			      const odp_tm_wred_params_t *params);

/** odp_tm_wred_lookup() can be used to find the WRED profile object created
 * with the specified name.
 *
 * @param name  Name of a previously created WRED profile.  Cannot be NULL.
 *
 * @return      Returns ODP_TM_INVALID upon failure, or the WRED
 *              profile handle created with this name.
 */
odp_tm_wred_t odp_tm_wred_lookup(const char *name);

/**
 * TM node parameters
 *
 * Many of these fields are optional EXCEPT for max_fanin and level. Use
 * odp_tm_node_params_init() to initialize parameters into their default values.
 */
typedef struct {
	/** The user_context field is an generic pointer that the user can
	 * associate with a tm_node and then get this same value back using
	 * the odp_tm_node_context() call. */
	void *user_context;

	/** The max_fanin sets the maximum number of src tm_queues and
	 * producer tm_nodes that can be simultaneously be connected to this
	 * tm_node as their destination. */
	uint32_t max_fanin;

	/** The shaper profile to be associated with this tm_node.  Can be
	 * ODP_TM_INVALID and can also be set and changed post-creation via
	 * odp_tm_node_shaper_config(); The default value is ODP_TM_INVALID. */
	odp_tm_shaper_t shaper_profile;

	/** The threshold profile to be used in setting the max queue fullness
	 * for WRED and/or tail drop?  Can be ODP_TM_INVALID and can also be
	 * set and changed post-creation via odp_tm_node_threshold_config().
	 * The default value is ODP_TM_INVALID. */
	odp_tm_threshold_t threshold_profile;

	/** The WRED profile(s) to be associated with this tm_node.  Any or
	 * all array elements can be ODP_TM_INVALID and can also be set and
	 * changed post-creation via odp_tm_node_wred_config().
	 * The default value is ODP_TM_INVALID for every color. */
	odp_tm_wred_t wred_profile[ODP_NUM_PACKET_COLORS];

	/** The level (or tm_node stage) sets the level for this tm_node It
	 * must be in range 0..max_levels-1.  Note that the tm_node topology
	 * is constrained such that only tm_node outputs with numerically
	 * greater levels may be connected to the fan-in of tm_node's with
	 * numerically smaller levels. */
	uint8_t level;

	/** New strict priority level assigned to packets going through this
	 * node when packet priority mode is ODP_TM_PKT_PRIO_MODE_OVERWRITE.
	 * In other packet priority modes this field is ignored. The new
	 * priority does not affect packet processing in this node but in
	 * its destination node.
	 *
	 * The value must be in the range 0..ODP_TM_MAX_PRIORITIES-1.
	 * Additionally, the total number of possible priorities seen by
	 * the destination node must not exceed the max priority configured
	 * for the destination node.
	 *
	 * @see odp_tm_pkt_prio_mode_t
	 * @see odp_tm_level_requirements_t::max_priority
	 */
	uint8_t priority;
} odp_tm_node_params_t;

/**
 * Initialize TM node parameters
 *
 * Initialize an odp_tm_node_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_node_params_t to be initialized
 */
void odp_tm_node_params_init(odp_tm_node_params_t *params);

/** Create an tm_node with a specific set of implemented strict priority
 * levels as given by the priorities array parameter.  The set of priority
 * levels does not have to "contiguous", but the "priorities" values for all
 * indexes > max_priority MUST be FALSE.  Note that the set of implemented
 * strict priority levels for an tm_node cannot be changed after tm_node
 * creation.  The level parameter MUST be in the range 0..max_level - 1.
 *
 * @param tm      Handle of the TM system into which this odp_tm_node object is
 *                created.
 * @param name    Optional name that can be used later later to find this
 *                same odp_tm_node_t.  Can be NULL, otherwise must be
 *                unique across all odp_tm_node objects.
 * @param params  TM node parameters.
 *
 * @return        Returns ODP_TM_INVALID upon failure, otherwise returns
 *                a valid odp_tm_node_t handle if successful.
 */
odp_tm_node_t odp_tm_node_create(odp_tm_t tm, const char *name,
				 const odp_tm_node_params_t *params);

/** Destroy  a tm_node object.
 *
 * The odp_tm_node_destroy frees the resources used by a tm_node_t object.
 * The tm_node to be destroyed MUST not have any parent or child entities.
 *
 * @param tm_node  Specifies the tm_node to be destroyed (freed).
 * @return         Returns -1 upon failure, 0 upon success.
 */
int odp_tm_node_destroy(odp_tm_node_t tm_node);

/** The odp_tm_node_shaper_config() function is used to dynamically set or
 * change the shaper profile associated with this tm_node.
 *
 * @param tm_node         Specifies the tm_node to be changed.
 * @param shaper_profile  Specifies the shaper profile that should
 *                        now be used for the shaper entity within the
 *                        given tm_node.  Note that it is legal to specify
 *                        ODP_TM_INVALID indicating that this tm_node
 *                        no longer implements a shaper function.
 * @return                Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_node_shaper_config(odp_tm_node_t tm_node,
			      odp_tm_shaper_t shaper_profile);

/** The odp_tm_node_sched_config() function is used to dynamically set or
 * change the scheduler profile associated with a tm_node.
 *
 * @param tm_node         Specifies the tm_node to be changed.
 * @param tm_fan_in_node  Specifies which of the specified tm_node's
 *                        fan-in's weights etc are to be changed. The
 *                        fan-in is identified by the "producer"/parent
 *                        tm_node actually connected to this fan-in.
 * @param sched_profile   Specifies the scheduler profile that should
 *                        now be used for the WFQ/RR entity within the
 *                        given tm_node.
 * @return                Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_node_sched_config(odp_tm_node_t tm_node,
			     odp_tm_node_t tm_fan_in_node,
			     odp_tm_sched_t sched_profile);

/** The odp_tm_node_threshold_config() function is used to dynamically set or
 * change the queue threshold profile associated with this tm_node.
 *
 * @param tm_node             Specifies the tm_node to be changed.
 * @param thresholds_profile  Specifies the queue threshold profile that
 *                            should now be used for the given tm_node.
 * @return                    Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_node_threshold_config(odp_tm_node_t tm_node,
				 odp_tm_threshold_t thresholds_profile);

/** The odp_tm_node_wred_config() function is used to dynamically set or
 * change the WRED profile associated with this tm_node or tm_node/pkt_color
 * combination.
 *
 * @param tm_node       Specifies the tm_node to be changed.
 * @param pkt_color     Specifies the pkt_color that this profile is to be
 *                      used with.  Can also be the special value
 *                      ALL_PKT_COLORS.
 * @param wred_profile  Specifies the WRED profile that should now be used
 *                      by this tm_queue, when processing pkts of this
 *                      pkt_color.  It can be the value ODP_TM_INVALID
 *                      indicating that this tm_queue/pkt_color combination
 *                      no longer implements WRED.
 * @return              Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_node_wred_config(odp_tm_node_t tm_node,
			    odp_packet_color_t pkt_color,
			    odp_tm_wred_t wred_profile);

/** odp_tm_node_lookup() can be used to find the tm_node object created with
 * the specified name.
 *
 * @param tm      TM handle
 * @param name    Name of a previously created tm_node.  Cannot be NULL.
 *
 * @return        Returns ODP_TM_INVALID upon failure, or the tm_node
 *                handle created with this name.
 */
odp_tm_node_t odp_tm_node_lookup(odp_tm_t tm, const char *name);

/** odp_tm_node_context() can be used to get the user_context value that is
 * associated with the given tm_node.
 *
 * @param tm_node Specifies the tm_node whose user_context is to be gotten.
 * @return        Returns the user_context pointer associated with this
 *                tm_node.  Returns NULL if the tm_node is not valid OR
 *                if the user_context was NULL.
 */
void *odp_tm_node_context(odp_tm_node_t tm_node);

/** odp_tm_node_context_set() can be used to set the user_context value that is
 * associated with the given tm_node.
 *
 * @param tm_node       Specifies the tm_node whose user_context is to be set.
 * @param user_context  Generic pointer associated with the given tm_node.
 *                      Does not have any effect on the tm_node semantics.
 * @return              Returns 0 upon success and -1 if the given tm_node
 *                      is not valid.
 */
int odp_tm_node_context_set(odp_tm_node_t tm_node, void *user_context);

/**
 * TM queue parameters
 *
 * Use odp_tm_queue_params_init() to initialize parameters into their default
 * values.
 */
typedef struct {
	/** The user_context field is an generic pointer that the user can
	 * associate with a tm_queue and then get this same value back using
	 * the odp_tm_queue_context() call. */
	void *user_context;

	/** The shaper profile to be associated with this tm_queue.  Can be
	 * ODP_TM_INVALID and can also be set and changed post-creation via
	 * odp_tm_queue_shaper_config(). The default value is ODP_TM_INVALID. */
	odp_tm_shaper_t shaper_profile;

	/** The threshold profile to be used in setting the max queue fullness
	 * for WRED and/or tail drop?  Can be ODP_TM_INVALID and can also be
	 * set and changed post-creation via odp_tm_queue_threshold_config().
	 * The default value is ODP_TM_INVALID. */
	odp_tm_threshold_t threshold_profile;

	/** The WRED profile(s) to be associated with this tm_queue.  Any or
	 * all array elements can be ODP_TM_INVALID and can also be set and
	 * changed post-creation via odp_tm_queue_wred_config().
	 * The default value is ODP_TM_INVALID for every color. */
	odp_tm_wred_t wred_profile[ODP_NUM_PACKET_COLORS];

	/** The strict priority level assigned to packets in this tm_queue -
	 * in other words all packets associated with a given tm_queue MUST
	 * have the same single strict priority level and this level must be
	 * in the range 0..max_priority. The default value is 0. */
	uint8_t priority;

	/** Maintain original packet order of the source queue when enqueuing
	 * packets to this queue while holding ordered or atomic queue
	 * synchronization context. Default value of this flag is true.
	 */
	odp_bool_t ordered_enqueue;
} odp_tm_queue_params_t;

/**
 * Initialize TM queue parameters
 *
 * Initialize an odp_tm_queue_params_t to its default values for all fields.
 *
 * @param params  Address of the odp_tm_queue_params_t to be initialized
 */
void odp_tm_queue_params_init(odp_tm_queue_params_t *params);

/** Create an tm_queue object.  One can specify the maximum queue limits
 * either as a maximum number of packets in the queue OR as a maximum number
 * of bytes in the queue, or if both are specified, then whichever limit is
 * hit first.  Note that in the case of specifying the maximum queue memory
 * size as bytes, the system is free to instead convert this byte value into a
 * number of buffers and instead limit the queue memory usage by buffer counts
 * versus strictly using byte counts.
 *
 * @param tm      Handle of the TM system into which this odp_tm_queue object is
 *                created.
 * @param params  TM queue parameters.
 *
 * @return        Returns ODP_TM_INVALID upon failure, otherwise a valid
 *                odp_tm_queue_t handle.
 */
odp_tm_queue_t odp_tm_queue_create(odp_tm_t tm,
				   const odp_tm_queue_params_t *params);

/** Destroy an tm_queue object. The odp_tm_queue_destroy frees the resources
 * used by a tm_queue_t object.  The tm_queue to be destroyed MUST not be
 * connected in a tm system, and consequently cannot contain any pkts.
 *
 * @param tm_queue  Specifies the tm_queue to be destroyed (freed).
 * @return          Returns -1 upon failure, 0 upon success.
 */
int odp_tm_queue_destroy(odp_tm_queue_t tm_queue);

/** odp_tm_queue_context() can be used to get the user_context value that is
 * associated with the given tm_queue.
 *
 * @param tm_queue  Specifies the tm_queue whose user_context is to be
 *                  returned.
 * @return          Returns the user_context pointer associated with this
 *                  tm_queue. Returns NULL if the tm_queue is not valid OR
 *                  if the user_context was NULL.
 */
void *odp_tm_queue_context(odp_tm_queue_t tm_queue);

/** odp_tm_queue_context_set() can be used to set the user_context value that is
 * associated with the given tm_queue.
 *
 * @param tm_queue      Specifies the tm_queue whose user_context is to be set.
 * @param user_context  Generic pointer associated with the given tm_queue.
 *                      Does not have any effect on the tm_queue semantics.
 * @return              Returns 0 upon success and -1 if the given tm_queue
 *                      is not valid.
 */
int odp_tm_queue_context_set(odp_tm_queue_t tm_queue, void *user_context);

/** The odp_tm_queue_shaper_config() function is used to dynamically set
 * or change the shaper profile associated with this tm_queue.
 *
 * @param tm_queue        Specifies the tm_queue to be changed.
 * @param shaper_profile  Specifies the shaper profile that should now be
 *                        used for shaping the tm_queue's packet stream.
 *                        Note that it is legal to specify ODP_TM_INVALID
 *                        indicating that this tm_queue no longer
 *                        implements a shaper function.
 * @return                Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_queue_shaper_config(odp_tm_queue_t tm_queue,
			       odp_tm_shaper_t shaper_profile);

/** The odp_tm_queue_sched_config() function is used to dynamically set or
 * change the scheduler profile associated with a tm_node.  Note that despite
 * the name, this function affects a tm_node scheduler - specifically the
 * scheduler fan-in when such fan-in comes from an tm_queue.
 *
 * @param tm_node         Specifies the tm_node to be changed.
 * @param tm_fan_in_queue Specifies which of the specified tm_node's
 *                        fan-in's weights etc are to be changed. The
 *                        fan-in is identified by the "producer"/parent
 *                        tm_queue actually connected to this fan-in.
 * @param sched_profile   Specifies the scheduler profile that should
 *                        now be used for the WFQ/RR entity within the
 *                        given tm_node.
 * @return                Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_queue_sched_config(odp_tm_node_t tm_node,
			      odp_tm_queue_t tm_fan_in_queue,
			      odp_tm_sched_t sched_profile);

/** The odp_tm_queue_threshold_config() function is used to dynamically set or
 * change the queue threshold profile associated with this tm_queue.
 *
 * @param tm_queue            Specifies the tm_queue to be changed.
 * @param thresholds_profile  Specifies the queue threshold profile that
 *                            should now be used for the given tm_queue.
 * @return                    Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_queue_threshold_config(odp_tm_queue_t tm_queue,
				  odp_tm_threshold_t thresholds_profile);

/** odp_tm_queue_wred_config() function is used to dynamically set or change
 * the WRED profile associated with this tm_queue or tm_queue/pkt_color
 * combination.
 *
 * @param tm_queue      Specifies the tm_queue to be changed.
 * @param pkt_color     Specifies the pkt_color that this profile is to be
 *                      used with.  Can also be the special value
 *                      ALL_PKT_COLORS.
 * @param wred_profile  Specifies the WRED profile that should now be used
 *                      by this tm_queue, when processing pkts of this
 *                      pkt_color.  It can be the value ODP_TM_INVALID
 *                      indicating that this tm_queue/pkt_color combination
 *                      no longer implements WRED.
 * @return              Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_queue_wred_config(odp_tm_queue_t tm_queue,
			     odp_packet_color_t pkt_color,
			     odp_tm_wred_t wred_profile);

/* Topology setting functions
 * -------------------------------------------------------- */

/** Connects two tm_nodes
 *
 * Connects the "output" of the src_tm_node to be a "producer" of the given
 * dst_tm_node.  Note that an ODP_TM_ROOT handle passed in for the
 * dst_tm_node implies connection to the egress/root object of this TM system.
 *
 * @param src_tm_node  odp_tm_node_t handle of the tm_node whose output is
 *                     to be connected to the fan-in of the next tm_node
 *                     as represented by the dst_tm_node.
 * @param dst_tm_node  odp_tm_node_t handle of the tm_node object that will
 *                     receive all of the pkt_descs from the src tm_node
 *                     output.  If ODP_TM_ROOT, then attachment is to
 *                     the root egress object/spigot.
 * @return             0 upon success, < 0 on failure.
 */
int odp_tm_node_connect(odp_tm_node_t src_tm_node, odp_tm_node_t dst_tm_node);

/** Disconnect a tm_node to tm_node linkage.
 *
 * The odp_tm_node_disconnect() function is used to disconnect a given
 * tm_node from its fanout.  This function requires that no active, enabled
 * tm_queue to be in the fanin tree (directly or indirectly) of this tm_node.
 * Note that it is legal for this tm_node to no fanout connection.
 *
 * @param src_tm_node  odp_tm_node_t handle of the tm_node whose output is
 *                     to be disconnected from the fan-in of the next tm_node.
 *
 * @return             0 upon success, < 0 on failure.
 */
int odp_tm_node_disconnect(odp_tm_node_t src_tm_node);

/** The odp_tm_queue_connect() function connects the indicated tm_queue to a
 * parent tm_node or to the egress/root node.  The tm_queue will then become
 * one of the dst node's fan-in set.
 *
 * @param tm_queue     Specifies the tm_queue.
 * @param dst_tm_node  odp_tm_node_t handle of the tm_node object that will
 *                     receive all of the pkt_descs from the src tm_node
 *                     output.  If ODP_TM_ROOT, then attachment is to
 *                     the root egress object/spigot.
 * @return             Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_queue_connect(odp_tm_queue_t tm_queue, odp_tm_node_t dst_tm_node);

/** Disconnect a tm_queue from a tm_system.
 *
 * The odp_tm_queue_disconnect() function is used to disconnect a given
 * tm_queue from its fanout. Note that it is legal for this tm_queue to
 * have no fanout connection.
 *
 * @param tm_queue     Specifies the tm_queue.
 * @return             0 upon success, < 0 on failure.
 */
int odp_tm_queue_disconnect(odp_tm_queue_t tm_queue);

/* Input API
 * -------------------------------------------------------- */

/** The odp_tm_enq() function is used to add packets to a given TM system.
 * Note that the System Metadata associated with the pkt needed by the TM
 * system is (a) a drop_eligible bit, (b) a two bit "pkt_color", (c) a 16-bit
 * pkt_len, and MAYBE? (d) a signed 8-bit shaper_len_adjust.
 *
 * If there is a non-zero shaper_len_adjust, then it is added to the pkt_len
 * after any non-zero shaper_len_adjust that is part of the shaper profile.
 *
 * The pkt_color bits are a result of some earlier Metering/Marking/Policing
 * processing.
 *
 * @param tm_queue  Specifies the tm_queue (and indirectly the TM system).
 * @param pkt       Handle to a packet.
 * @return          Returns 0 upon success, < 0 upon failure. One of the
 *                  more common failure reasons is WRED drop.
 */
int odp_tm_enq(odp_tm_queue_t tm_queue, odp_packet_t pkt);

/** The odp_tm_enq_multi() function is used to add packets to a given TM system.
 * This function enqueues multiple packets but is otherwise similar to
 * odp_tm_enq(). Packets dropped by WRED or other queue management action do not
 * cause this function to return a failure. Such packets get consumed just like
 * the packets that are not dropped.
 *
 * When the return value is less than 'num', the remaining packets at the end of
 * the array are not consumed, and the caller maintains ownership of those.
 *
 * @param tm_queue  Specifies the tm_queue (and indirectly the TM system).
 * @param packets   Array of packets to enqueue.
 * @param num       Number of packets to enqueue.
 *
 * @return Number of packets consumed (0 ... num)
 * @retval <0 on failure.
 */
int odp_tm_enq_multi(odp_tm_queue_t tm_queue, const odp_packet_t packets[], int num);

/** Send packets with segmentation offload to TM system
 *
 * Like odp_tm_enq_multi(), but segments packets according LSO configuration. See e.g.
 * odp_pktout_send_lso() for documentation how packets are split into smaller packets during
 * the segmentation offload. Packet segmentation is done first and TM functionality is applied
 * to the resulting packets.
 *
 * @param tm_queue  Specifies the tm_queue (and indirectly the TM system)
 * @param packets   Array of packets to enqueue with segmentation offload
 * @param num       Number of packets in the array
 * @param lso_opt   LSO options to be used for all packets. When NULL, LSO options are
 *                  read from each packet (see odp_packet_lso_request()).
 *
 * @return Number of packets successfully processed and consumed (0 ... num)
 * @retval <0 on failure
 */
int odp_tm_enq_multi_lso(odp_tm_queue_t tm_queue, const odp_packet_t packets[], int num,
			 const odp_packet_lso_opt_t *lso_opt);

/** The odp_tm_enq_with_cnt() function behaves identically to odp_tm_enq(),
 * except that it also returns (an approximation to?) the current tm_queue
 * packet queue count.
 *
 * @param tm_queue  Specifies the tm_queue (and indirectly the TM system).
 * @param pkt       Handle to a packet.
 * @return          Returns the number of packets previously enqueued on
 *                  this tm_queue upon success, < 0 upon failure.
 */
int odp_tm_enq_with_cnt(odp_tm_queue_t tm_queue, odp_packet_t pkt);

/* Dynamic state query functions
 * -------------------------------------------------------- */

/** The odp_tm_node_info_t record type  is used to return various bits of
 * information about a given tm_node via the odp_tm_node_info() function.
 */
typedef struct {
	/** The shaper profile currently associated with this tm_node.  Can be
	 * ODP_TM_INVALID indicating no shaper profile is associated. */
	odp_tm_shaper_t shaper_profile;

	/** The threshold profile currently associated with this tm_node.  Can
	 * be ODP_TM_INVALID indicating no threshold profile is associated. */
	odp_tm_threshold_t threshold_profile;

	/** The WRED profile(s) currently associated with this tm_node.  Any
	 * or all array elements can be ODP_TM_INVALID indicating no WRED
	 * profile is associated  with this tm_node/ color combination. */
	odp_tm_wred_t wred_profile[ODP_NUM_PACKET_COLORS];

	/** Current tm_queue fanin. */
	uint32_t tm_queue_fanin;

	/** Current tm_node fanin. */
	uint32_t tm_node_fanin;

	/** The next_tm_node is the "next" node in the tree - i.e. the fanout
	 * of this node.  Can be ODP_TM_ROOT if this tm_node directly connects
	 * to the egress spigot and can be ODP_TM_INVALID if this tm_node is
	 * disconnected from the TM system tree, */
	odp_tm_node_t next_tm_node;

	/** The level of this tm_node.  Note that this value cannot be modified
	 * after a tm_node has been created, */
	uint8_t level;
} odp_tm_node_info_t;

/** Get tm_node Info
 *
 * The odp_tm_node_info() function is used to extract various bits of
 * configuration associated with a given tm_node. The info structure is written
 * only on success.
 *
 * @param      tm_node  Specifies the tm_node to be queried.
 * @param[out] info     A pointer to an odp_tm_node_info_t record that is to
 *                      be filled in by this call.
 * @return              Returns < 0 upon failure, 0 upon success.
 */
int odp_tm_node_info(odp_tm_node_t tm_node, odp_tm_node_info_t *info);

/** The odp_tm_node_fanin_info_t record type is used to return various bits of
 * information about a given "link"/"connection"/"fanin" between a tm_queue
 * and a tm_node OR between a tm_node and a tm_node,  It is also used as the
 * state needed to implement an iterator that walks the complete fanin list
 * of a given tm_node.
 */
typedef struct {
	/** The sched profile currently associated with this fanin link.  This
	 * can be ODP_TM_INVALID indicating no sched profile is associated. */
	odp_tm_sched_t sched_profile;

	/** The tm_queue indicates the "producer" of this fanin. Note that
	 * that at most one of tm_queue and tm_node can be valid
	 * here (i.e. not equal to ODP_TM_INVALID). */
	odp_tm_queue_t tm_queue;

	/** The tm_node indicates the "producer" of this fanin. Note that
	 * that at most one of tm_queue and tm_node can be valid
	 * here (i.e. not equal to ODP_TM_INVALID). */
	odp_tm_node_t tm_node;

	/** The is_last flag is set when the tm_queue/tm_node above is
	 * currently the last element in the fanin list. */
	odp_bool_t is_last;
} odp_tm_node_fanin_info_t;

/** Get tm_node Fanin Info
 *
 * The odp_tm_node_fanin_info() function is used to extract various bits of
 * configuration associated with a given tm_node's fanin.  It can also be
 * used to walk the complete fanin list of a given tm_node.  Note in particular
 * that the odp_tm_node_fanin_info_t record passed to this function is both
 * an input AND output parameter.  The semantics are that the application
 * first clears the tm_queue, tm_node and is_last fields (to TM_ODP_INVALID,
 * TM_ODP_INVALID and false respectively) before making its first call to
 * odp_tm_node_fanin_info().  The fact that tm_queue and tm_node are both
 * TM_ODP_INVALID indicates that the caller wants the FIRST entry in the
 * given tm_node's fanin list.  It will then update either the tm_queue or
 * tm_node field in the info record with this first entry.  On subsequent calls
 * to this function, exactly one of the tm_queue or tm_node field will be !=
 * TM_ODP_INVALID, and this function will then replace the tm_queue and
 * tm_node fields with the NEXT entry in this tm_node's fanin list.  If this
 * next entry is also the last entry then is_last will also be set.
 * Note that this function will fail (returning < 0 code) if the incoming
 * is_last field is set.
 * In general walking a fanin list while it is being changed (via _connect() or
 * _disconnect() calls) is problematic - BUT as long as the incoming
 * tm_queue/tm_node values refer to entities that have not been disconnected
 * from their fanin list, a reasonable list walk can occur - even while past or
 * future entries are being removed or while future entries are being added.
 * Note that all new additions to a fanin list always take place at the end of
 * the list. The info structure is written only on success.
 *
 * @param         tm_node  Specifies the tm_node to be queried.
 * @param[in,out] info     A pointer to an odp_tm_node_fanin_info_t record that
 *                         is used to determine which fanin entry is to be
 *                         next filled in by this call.
 * @return                 Returns < 0 upon failure, 0 upon success.
 */
int odp_tm_node_fanin_info(odp_tm_node_t             tm_node,
			   odp_tm_node_fanin_info_t *info);

/** The odp_tm_queue_info_t record type  is used to return various bits of
 * information about a given tm_queue via the odp_tm_queue_info() function.
 */
typedef struct {
	/** The shaper profile currently associated with this tm_queue.  Can be
	 * ODP_TM_INVALID indicating no shaper profile is currently associated
	 * with this tm_queue. */
	odp_tm_shaper_t shaper_profile;

	/** The threshold profile currently associated with this tm_queue.  Can
	 * be ODP_TM_INVALID indicating no threshold profile is currently
	 * associated with this tm_queue. */
	odp_tm_threshold_t threshold_profile;

	/** The WRED profile(s) currently associated with this tm_queue.  Any
	 * or all array elements can be ODP_TM_INVALID indicating no WRED
	 * profile is currently associated  with this tm_queue/color
	 * combination. */
	odp_tm_wred_t wred_profile[ODP_NUM_PACKET_COLORS];

	/** The next_tm_node is the "next" node in the tree - i.e. the fanout
	 * of this tm_queue. Can be ODP_TM_ROOT if this tm_queue directly
	 * connects to the egress spigot and can be ODP_TM_INVALID if this
	 * tm_queue is disconnected from the TM system tree. */
	odp_tm_node_t next_tm_node;

	/** The active_pkt is the current packet "at the head of the queue"
	 * that is being processed by this tm_queue. */
	odp_packet_t active_pkt;
} odp_tm_queue_info_t;

/** Get tm_queue Info
 *
 * The odp_tm_queue_info() function is used to extract various bits of
 * configuration associated with a given tm_queue. The info structure is
 * written only on success.
 *
 * @param      tm_queue  Specifies the tm_queue to be queried.
 * @param[out] info      A pointer to an odp_tm_queue_info_t record that is to
 *                       be filled in by this call.
 * @return               Returns < 0 upon failure, 0 upon success.
 */
int odp_tm_queue_info(odp_tm_queue_t tm_queue, odp_tm_queue_info_t *info);

/** The following bit mask constants are used to refine the queue query
 * functions defined below.
 */
#define ODP_TM_QUERY_PKT_CNT     0x01   /**<  The total_pkt_cnt value */
#define ODP_TM_QUERY_BYTE_CNT    0x02   /**<  The total_byte_cnt value */
#define ODP_TM_QUERY_THRESHOLDS  0x04   /**<  The thresholds??? */

/** The odp_tm_query_info_t record type is used to return the various counts
 * as requested by functions like odp_tm_queue_query() and
 * odp_tm_total_query().
 */
typedef struct {
	/** The total_pkt_cnt field is the total number of packets currently
	 * stored/associated with the requested set of tm_queues.  Note that
	 * because the packet queues are potentially being manipulated by
	 * multiple cpu's, the values here are only accurate when the tm
	 * system is "stopped" (i.e. the egress spigot is stopped and no
	 * odp_tm_enq calls are taking place).  Implementations are free to
	 * batch update these counters - up to a dozen or so packets. */
	uint64_t total_pkt_cnt;

	/** If the requested set of tm_queues has an odp_tm_threshold_t
	 * profile associated with it, then this is the max_pkt_cnt set in the
	 * profile params.  Returning this field is a convenience to the ODP
	 * programmer, enabling them to quickly see how the total_pkt_cnt
	 * compares to the maximum packet count threshold.  Note that there is
	 * no requirement that total_pkt_cnt be <= max_pkt_cnt. */
	uint64_t max_pkt_cnt;

	/** The total_byte_cnt can either be the actual number of bytes used
	 * or an approximation of the number of bytes used based upon the
	 * number of fixed sized buffers used multiplied by the buffer size.
	 * In both cases the total_byte_cnt should correspond to the same set
	 * of packets that were counted above.  For instance, if the
	 * total_pkt_cnt is updated in a batch, then the total_byte_cnt should
	 * also be updated in the same batch.  The approx_byte_cnt field below
	 * indicates whether the total_byte_cnt is buffer count based or not.
	 * In the case that the number of bytes used by a packet is rounded up
	 * to a 2, 4, 8, or 16 byte boundary, it is recommended that
	 * approx_byte_cnt be false.  It is implementation dependent whether
	 * the byte count of a packet includes the CRC, but it is recommended
	 * that it not include headroom, preamble or IPG.  Of course when the
	 * buffer counting method is used, it is expected that any headroom in
	 * the first buffer is implicitly included.  Finally in the case of
	 * variable length pkt based buffering, instead of taking the
	 * total_pkt_cnt and multiplying it by the maximum ethernet packet
	 * size, it is recommended that byte_cnt_valid be FALSE - even when
	 * query_flags includes ODP_TM_QUERY_BYTE_CNT.*/
	uint64_t total_byte_cnt;

	/** If the requested set of tm_queues has an odp_tm_threshold_t
	 * profile associated with it, then this is the max_byte_cnt set in
	 * the profile params.  Returning this field is a convenience to the
	 * ODP programmer, enabling them to quickly see how the total_byte_cnt
	 * compares to the maximum byte count threshold.  Note that there is
	 * no requirement that total_byte_cnt be <= max_byte_cnt. */
	uint64_t max_byte_cnt;

	/** The following boolean values indicate which of the counts above
	 * are valid.  Invalid count values must be 0. */
	odp_bool_t total_pkt_cnt_valid;  /**< TRUE if total_pkt_cnt is valid */
	odp_bool_t max_pkt_cnt_valid;    /**< TRUE if max_pkt_cnt is valid */
	odp_bool_t total_byte_cnt_valid; /**< TRUE if total_byte_cnt is valid */
	odp_bool_t max_byte_cnt_valid;   /**< TRUE if max_byte_cnt is valid */

	/** The approx_byte_cnt is TRUE if the total_byte_cnt field is valid
	 * AND if the buffer counting method is used. */
	odp_bool_t approx_byte_cnt;
} odp_tm_query_info_t;

/** The odp_tm_queue_query() function can be used to check a single tm_queue's
 * queue utilization.  The query flags indicate which information is being
 * requested.
 * The implementation may choose to return additional information that was not
 * requested. The info structure is written only on success.
 *
 * @param      tm_queue     Specifies the tm_queue (and indirectly the
 *                          TM system).
 * @param      query_flags  A set of flag bits indicating which counters are
 *                          being requested to be returned in the info record.
 * @param[out] info         Pointer to an odp_tm_query_info_t record where the
 *                          requested queue info is returned.
 * @return                  Returns 0 upon success, < 0 upon failure.
 */
int odp_tm_queue_query(odp_tm_queue_t       tm_queue,
		       uint32_t             query_flags,
		       odp_tm_query_info_t *info);

/** The odp_tm_priority_query() function can be used to check the queue
 * utilization of all tm_queue's with the given priority.  The query flags
 * indicate which information is being requested. The implementation may
 * choose to return additional information that was not requested.
 * The info structure is written only on success.
 *
 * @param      odp_tm       Specifies the TM system.
 * @param      priority     Supplies the strict priority level used to specify
 *                          which tm_queues are included in the info values.
 * @param      query_flags  A set of flag bits indicating which counters are
 *                          being requested to be returned in the info record.
 * @param[out] info         Pointer to an odp_tm_query_info_t record where the
 *                          requested queue info is returned.
 * @return                  Returns 0 upon success, < 0 upon failure.
 */
int odp_tm_priority_query(odp_tm_t             odp_tm,
			  uint8_t              priority,
			  uint32_t             query_flags,
			  odp_tm_query_info_t *info);

/** The odp_tm_total_query() function can be used to check the queue
 * utilization of all tm_queue's in a single TM system.  The query_flags
 * indicate which information is being requested. The implementation may
 * choose to return additional information that was not requested.
 * The info structure is written only on success.
 *
 * @param      odp_tm       Specifies the TM system.
 * @param      query_flags  A set of flag bits indicating which counters are
 *                          being requested to be returned in the info record.
 * @param[out] info         Pointer to an odp_tm_query_info_t record where the
 *                          requested queue info is returned.
 * @return                  Returns 0 upon success, < 0 upon failure.
 */
int odp_tm_total_query(odp_tm_t             odp_tm,
		       uint32_t             query_flags,
		       odp_tm_query_info_t *info);

/** The odp_tm_priority_threshold_config() function is only used to associate
 * a maximum packet count and/or a maximum byte count with a strict priority
 * level - for the benefit of the odp_tm_priority_query() function.  It has no
 * semantic effects other than returning these queue threshold values in the
 * odp_tm_query_info_t record.
 *
 * @param odp_tm              Specifies the TM system.
 * @param priority            Supplies the strict priority level that
 *                            the threshold profile params are associated with.
 *
 * @param thresholds_profile  Specifies the queue threshold profile that
 *                            should now be associated with the supplied
 *                            strict priority level.
 * @return                    Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_priority_threshold_config(odp_tm_t           odp_tm,
				     uint8_t            priority,
				     odp_tm_threshold_t thresholds_profile);

/** The odp_tm_total_threshold_config() function is only used to associate a
 * maximum packet count and/or a maximum byte count with a TM system - for the
 * benefit of the odp_tm_total_query() function.  It has no semantic effects
 * other than returning these queue threshold values in the
 * odp_tm_query_info_t record.
 *
 * @param tm                  TM handle
 * @param thresholds_profile  Specifies the queue threshold profile that
 *                            should now be used for the entire TM
 *                            system.
 *
 * @return                    Returns 0 upon success and < 0 upon failure.
 */
int odp_tm_total_threshold_config(odp_tm_t tm,
				  odp_tm_threshold_t thresholds_profile);

/** The odp_tm_is_idle function is used to determine if the specified ODP
 * traffic management system still has "work" to do (i.e. has at least one
 * non-empty tm_queue and perhaps some outstanding timers etc).  This function
 * can be used by test programs and ODP applications that wish to know when
 * TM system has completed its work - presumably after they have stopped
 * sending in new pkts.  Note that this function should not be called often
 * since for some implementations this call could take a fairly long time
 * to execute!
 *
 * @param tm      TM handle
 *
 * @return        Returns 1 if the TM system is idle and 0 otherwise.
 */
odp_bool_t odp_tm_is_idle(odp_tm_t tm);

/** The odp_tm_stats_print function is used to write implementation-defined
 * information about the specified TM system to the ODP log. The intended use
 * is for debugging.
 *
 * @param tm      TM handle
 */
void odp_tm_stats_print(odp_tm_t tm);

/**
 * Get statistics for a TM queue
 *
 * Counters not supported by the queue are set to zero.
 *
 * It's implementation defined if odp_pktio_stats_reset() call affects these
 * counters.
 *
 * @param      tm_queue TM queue handle
 * @param[out] stats    Statistics structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_tm_queue_stats(odp_tm_queue_t tm_queue, odp_tm_queue_stats_t *stats);

/**
 * Get printable value for an odp_tm_t
 *
 * @param tm   TM handle
 *
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_t handle.
 */
uint64_t odp_tm_to_u64(odp_tm_t tm);

/**
 * Get printable value for an odp_tm_queue_t
 *
 * @param hdl  odp_tm_queue_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_queue_t handle.
 */
uint64_t odp_tm_queue_to_u64(odp_tm_queue_t hdl);

/**
 * Get printable value for an odp_tm_node_t
 *
 * @param hdl  odp_tm_node_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_node_t handle.
 */
uint64_t odp_tm_node_to_u64(odp_tm_node_t hdl);

/**
 * Get printable value for an odp_tm_shaper_t
 *
 * @param hdl  odp_tm_shaper_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_shaper_t handle.
 */
uint64_t odp_tm_shaper_to_u64(odp_tm_shaper_t hdl);

/**
 * Get printable value for an odp_tm_sched_t
 *
 * @param hdl  odp_tm_sched_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_sched_t handle.
 */
uint64_t odp_tm_sched_to_u64(odp_tm_sched_t hdl);

/**
 * Get printable value for an odp_tm_threshold_t
 *
 * @param hdl  odp_tm_threshold_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_threshold_t handle.
 */
uint64_t odp_tm_threshold_to_u64(odp_tm_threshold_t hdl);

/**
 * Get printable value for an odp_tm_wred_t
 *
 * @param hdl  odp_tm_wred_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_tm_wred_t handle.
 */
uint64_t odp_tm_wred_to_u64(odp_tm_wred_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
