/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_API_SPEC_CLASSIFY_H_
#define ODP_API_SPEC_CLASSIFY_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet_io.h>
#include <odp/api/support.h>
#include <odp/api/threshold.h>
/** @defgroup odp_classification ODP CLASSIFICATION
 *  Classification operations.
 *  @{
 */

/**
 * @typedef odp_cos_t
 * ODP Class of service handle
 */

/**
 * @def ODP_COS_INVALID
 * This value is returned from odp_cls_cos_create() on failure,
 * May also be used as a sink class of service that
 * results in packets being discarded.
 */

/**
 * @def ODP_COS_NAME_LEN
 * Maximum ClassOfService name length in chars including null char
 */

/**
 * @def ODP_PMR_INVALID
 * Invalid odp_pmr_t value.
 * This value is returned from odp_cls_pmr_create()
 * function on failure.
 */

/**
 * @def ODP_PMR_INVAL
 * @deprecated Use ODP_PMR_INVALID instead
 */

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
		/** destination MAC address */
		uint64_t	dmac:1;
		/** IP Protocol or IPv6 Next Header */
		uint64_t	ip_proto:1;
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
		/** Custom match rule, offset from start of
		 * frame. The match is defined by the offset, the
		 * expected value, and its size.
		 */
		uint64_t	custom_frame:1;

	} bit;
	/** All bits of the bit field structure */
	uint64_t all_bits;
} odp_cls_pmr_terms_t;

/** Random Early Detection (RED)
 * Random Early Detection is enabled to initiate a drop probability for the
 * incoming packet when the packets in the queue/pool cross the specified
 * threshold values. RED is enabled when 'red_enable' boolean is true and
 * the resource usage is equal to or greater than the minimum threshold value.
 * Resource usage could be defined either as the percentage of pool being full
 * or the number of packets/bytes occupied in the queue depening on the platform
 * capabilities.
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
	 * Otherwise, RED parameters are ignored. */
	odp_bool_t enable;

	/** Threshold parameters for RED
	 * RED is enabled when the resource usage is equal to or greater than
	 * the minimum threshold value and is disabled otherwise
	 */
	odp_threshold_t threshold;
} odp_red_param_t;

/** Back pressure (BP)
 * When back pressure is enabled for a particular flow, the HW can send
 * back pressure information to the remote peer indicating a network congestion.
 */
typedef struct odp_bp_param_t {
	/** A boolean to enable Back pressure
	 * When true, back pressure is enabled and configured with the BP
	 * parameters. Otherwise BP parameters are ignored.
	 */
	odp_bool_t enable;

	/** Threshold value for back pressure.
	 * BP is enabled when the resource usage is equal to or greater than the
	 * max backpressure threshold. Min threshold parameters are ignored for
	 * BP configuration.
	 * @see odp_red_param_t for 'resource usage' documentation.
	 */
	odp_threshold_t threshold;
} odp_bp_param_t;

/**
 * Classification capabilities
 * This capability structure defines system level classification capability
 */
typedef struct odp_cls_capability_t {
	/** PMR terms supported by the classifier
	 * A bit mask of one bit for each of odp_pmr_term_t
	 */
	odp_cls_pmr_terms_t supported_terms;

	/** Maximum number of PMR terms */
	unsigned max_pmr_terms;

	/** Number of PMR terms available for use now */
	unsigned available_pmr_terms;

	/** Maximum number of CoS supported */
	unsigned max_cos;

	/** Maximun number of queue supported per CoS
	 * if the value is 1, then hashing is not supported*/
	unsigned max_hash_queues;

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
} odp_cls_capability_t;

/**
 * class of service packet drop policies
 */
typedef enum {
	ODP_COS_DROP_POOL,    /**< Follow buffer pool drop policy */
	ODP_COS_DROP_NEVER,    /**< Never drop, ignoring buffer pool policy */
} odp_cls_drop_t;

/**
 * Packet header field enumeration
 * for fields that may be used to calculate
 * the flow signature, if present in a packet.
 */
typedef enum {
	ODP_COS_FHDR_IN_PKTIO,	/**< Ingress port number */
	ODP_COS_FHDR_L2_SAP,	/**< Ethernet Source MAC address */
	ODP_COS_FHDR_L2_DAP,	/**< Ethernet Destination MAC address */
	ODP_COS_FHDR_L2_VID,	/**< Ethernet VLAN ID */
	ODP_COS_FHDR_L3_FLOW,	/**< IPv6 flow_id */
	ODP_COS_FHDR_L3_SAP,	/**< IP source address */
	ODP_COS_FHDR_L3_DAP,	/**< IP destination address */
	ODP_COS_FHDR_L4_PROTO,	/**< IP protocol (e.g. TCP/UDP/ICMP) */
	ODP_COS_FHDR_L4_SAP,	/**< Transport source port */
	ODP_COS_FHDR_L4_DAP,	/**< Transport destination port */
	ODP_COS_FHDR_IPSEC_SPI,	/**< IPsec session identifier */
	ODP_COS_FHDR_LD_VNI,	/**< NVGRE/VXLAN network identifier */
	ODP_COS_FHDR_USER	/**< Application-specific header field(s) */
} odp_cos_hdr_flow_fields_t;

/**
 * Class of service parameters
 * Used to communicate class of service creation options
 */
typedef struct odp_cls_cos_param {
	/** Number of queues to be linked to this CoS.
	 * If the number is greater than 1 then hashing is enabled.
	 * If number is equal to 1 then hashing is disabled.
	 * When hashing is enabled the queues are created by the implementation
	 * and application need not configure any queue to the class of service.
	 * When hashing is disabled application has to configure the queue to
	 * the class of service.
	 * Depening on the implementation this number might be rounded-off to
	 * nearest supported value (e.g power of 2)
	 */
	uint32_t num_queue;

	/** Variant mapping for queue hash configurataion */
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
	/** Pool associated with CoS */
	odp_pool_t pool;

	/** Drop policy associated with CoS */
	odp_cls_drop_t drop_policy;

	/** Random Early Detection configuration */
	odp_red_param_t red;

	/** Back Pressure configuration */
	odp_bp_param_t bp;
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
 * The use of class-of-service name is optional. Unique names are not required.
 *
 * @param name         Name of the class-of-service or NULL. Maximum string
 *                     length is ODP_COS_NAME_LEN.
 * @param param        Class-of-service parameters
 *
 * @retval Class-of-service handle
 * @retval ODP_COS_INVALID on failure.
 *
 * @note ODP_QUEUE_INVALID and ODP_POOL_INVALID are valid values for queue
 * and pool associated with a class of service and when any one of these values
 * are configured as INVALID then the packets assigned to the CoS gets dropped.
 */
odp_cos_t odp_cls_cos_create(const char *name, odp_cls_cos_param_t *param);

/**
 * Queue hash result
 * Returns the queue within a CoS in which a particular packet will be enqueued
 * based on the packet parameters and hash protocol field configured with the
 * class of service.
 *
 * @param cos          class of service
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
 * @param cos_id       class-of-service instance.
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cos_destroy(odp_cos_t cos_id);

/**
 * Assign a queue for a class-of-service
 *
 * @param cos_id       class-of-service instance.
 * @param queue_id     Identifier of a queue where all packets of this specific
 *                     class of service will be enqueued.
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id);

/**
* Get the queue associated with the specific class-of-service
*
* @param cos_id        class-of-service instance.
*
* @retval Queue handle associated with the given class-of-service
* @retval ODP_QUEUE_INVALID on failure
*/
odp_queue_t odp_cos_queue(odp_cos_t cos_id);

/**
 * Get the number of queues linked with the specific class-of-service
 *
 * @param cos_id       class-of-service instance.
 *
 * @return Number of queues linked with the class-of-service.
 */
uint32_t odp_cls_cos_num_queue(odp_cos_t cos_id);

/**
 * Get the list of queue associated with the specific class-of-service
 *
 * @param      cos_id  class-of-service instance.
 * @param[out] queue   Array of queue handles associated with
 *                     the class-of-service.
 * @param      num     Maximum number of queue handles to output.
 *
 * @return Number of queues linked with CoS
 * @retval on 0 failure
 */
uint32_t odp_cls_cos_queues(odp_cos_t cos_id, odp_queue_t queue[],
			    uint32_t num);

/**
 * Assign packet drop policy for specific class-of-service
 *
 * @param cos_id       class-of-service instance.
 * @param drop_policy  Desired packet drop policy for this class.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_cos_drop_set(odp_cos_t cos_id, odp_cls_drop_t drop_policy);

/**
* Get the drop policy configured for a specific class-of-service instance.
*
* @param cos_id        class-of-service instance.
*
* @retval Drop policy configured with the given class-of-service
*/
odp_cls_drop_t odp_cos_drop(odp_cos_t cos_id);

/**
 * Request to override per-port class of service
 * based on Layer-2 priority field if present.
 *
 * @param pktio_in     Ingress port identifier.
 * @param num_qos      Number of QoS levels, typically 8.
 * @param qos_table    Values of the Layer-2 QoS header field.
 * @param cos_table    Class-of-service assigned to each of the allowed
 *                     Layer-2 QOS levels.
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cos_with_l2_priority(odp_pktio_t pktio_in,
			     uint8_t num_qos,
			     uint8_t qos_table[],
			     odp_cos_t cos_table[]);

/**
 * Request to override per-port class of service
 * based on Layer-3 priority field if present.
 *
 * @param pktio_in       Ingress port identifier.
 * @param num_qos        Number of allowed Layer-3 QoS levels.
 * @param qos_table      Values of the Layer-3 QoS header field.
 * @param cos_table      Class-of-service assigned to each of the allowed
 *                       Layer-3 QOS levels.
 * @param l3_preference	 when true, Layer-3 QoS overrides L2 QoS when present.
 *
 * @retval  0 on success
 * @retval <0 on failure
 *
 * @note Optional.
 */
int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference);

/**
 * @typedef odp_pmr_t
 * PMR - Packet Matching Rule
 * Up to 32 bit of ternary matching of one of the available header fields
 */

/**
 * Packet Matching Rule field enumeration
 * for fields that may be used to calculate
 * the PMR, if present in a packet.
 */
typedef enum {
	ODP_PMR_LEN,		/**< Total length of received packet*/
	ODP_PMR_ETHTYPE_0,	/**< Initial (outer)
				Ethertype only (*val=uint16_t)*/
	ODP_PMR_ETHTYPE_X,	/**< Ethertype of most inner VLAN tag
				(*val=uint16_t)*/
	ODP_PMR_VLAN_ID_0,	/**< First VLAN ID (outer) (*val=uint16_t) */
	ODP_PMR_VLAN_ID_X,	/**< Last VLAN ID (inner) (*val=uint16_t) */
	ODP_PMR_DMAC,		/**< destination MAC address (*val=uint64_t)*/
	ODP_PMR_IPPROTO,	/**< IP Protocol or IPv6 Next Header
				(*val=uint8_t) */
	ODP_PMR_UDP_DPORT,	/**< Destination UDP port, implies IPPROTO=17*/
	ODP_PMR_TCP_DPORT,	/**< Destination TCP port implies IPPROTO=6*/
	ODP_PMR_UDP_SPORT,	/**< Source UDP Port (*val=uint16_t)*/
	ODP_PMR_TCP_SPORT,	/**< Source TCP port (*val=uint16_t)*/
	ODP_PMR_SIP_ADDR,	/**< Source IP address (uint32_t)*/
	ODP_PMR_DIP_ADDR,	/**< Destination IP address (uint32_t)*/
	ODP_PMR_SIP6_ADDR,	/**< Source IP address (uint8_t[16])*/
	ODP_PMR_DIP6_ADDR,	/**< Destination IP address (uint8_t[16])*/
	ODP_PMR_IPSEC_SPI,	/**< IPsec session identifier(*val=uint32_t)*/
	ODP_PMR_LD_VNI,		/**< NVGRE/VXLAN network identifier
				(*val=uint32_t)*/
	ODP_PMR_CUSTOM_FRAME,	/**< Custom match rule, offset from start of
				frame. The match is defined by the offset, the
				expected value, and its size. They must be
				applied before any other PMR.
				(*val=uint8_t[val_sz])*/

	/** Inner header may repeat above values with this offset */
	ODP_PMR_INNER_HDR_OFF = 32
} odp_cls_pmr_term_t;

/**
 * Packet Matching Rule parameter structure
 */
typedef struct odp_pmr_param_t {
	odp_cls_pmr_term_t  term;	/**< Packet Matching Rule term */

	/** True if the value is range and false if match */
	odp_bool_t range_term;

	/** Variant mappings for types of matches */
	union {
		/** Parameters for single-valued matches */
		struct {
			/** Value to be matched */
			const void	*value;

			/** Masked set of bits to be matched */
			const void	*mask;
		} match;

		/** Parameter for range value matches */
		struct {
			/** Start and End values are included in the range */
			/** start value of range */
			const void	*val_start;

			/** End value of range */
			const void	*val_end;
		} range;
	};
	uint32_t	val_sz;	 /**< Size of the term value */

	uint32_t	offset;  /**< User-defined offset in packet
				 Used if term == ODP_PMR_CUSTOM_FRAME only,
				 ignored otherwise */
} odp_pmr_param_t;

/**
 * Initialize packet matching rule parameters
 *
 * Initialize an odp_pmr_param_t to its default values for all fields
 *
 * @param param        Address of the odp_pmr_param_t to be initialized
 */
void odp_cls_pmr_param_init(odp_pmr_param_t *param);

/**
 * Create a packet match rule between source and destination class of service.
 * This packet matching rule is applied on all packets arriving at the source
 * class of service and packets satisfying this PMR are sent to the destination
 * class of service.
 * A composite PMR rule is created when the number of terms in the match rule
 * is more than one. The composite rule is considered as matching only if
 * the packet satisfies all the terms in Packet Match Rule.
 * The underlying platform may not support all or any specific combination
 * of value match rules, and the application should take care
 * of inspecting the return value when installing such rules, and perform
 * appropriate fallback action.
 *
 * @param terms        Array of odp_pmr_param_t entries, one entry per term
 *                     desired.
 * @param num_terms    Number of terms in the match rule.
 * @param src_cos      source CoS handle
 * @param dst_cos      destination CoS handle
 *
 * @return Handle to the Packet Match Rule.
 * @retval ODP_PMR_INVALID on failure
 */
odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
			     odp_cos_t src_cos, odp_cos_t dst_cos);

/**
 * Function to destroy a packet match rule
 * Destroying a PMR removes the link between the source and destination
 * class of service and this PMR will no longer be applied for packets arriving
 * at the source class of service. All the resource associated with the PMR
 * be release but the class of service will remain intact.
 * Depending on the implementation details, destroying a composite rule
 * may not guarantee the availability of hardware resources to create the
 * same or essentially similar rule.
 *
 * @param pmr_id       Identifier of the PMR to be destroyed
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_cls_pmr_destroy(odp_pmr_t pmr_id);

/**
* Assigns a packet pool for a specific class of service.
* All the packets belonging to the given class of service will
* be allocated from the assigned packet pool.
* The packet pool associated with class of service will supersede the
* packet pool associated with the pktio interface.
*
* @param cos_id        class of service handle
* @param pool_id       packet pool handle
*
* @retval  0 on success
* @retval <0 on failure
*/
int odp_cls_cos_pool_set(odp_cos_t cos_id, odp_pool_t pool_id);

/**
* Get the pool associated with the given class of service
*
* @param cos_id        class of service handle
*
* @retval pool handle of the associated pool
* @retval ODP_POOL_INVALID if no associated pool found or in case of an error
*/
odp_pool_t odp_cls_cos_pool(odp_cos_t cos_id);

/**
 * Get printable value for an odp_cos_t
 *
 * @param hdl          odp_cos_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_cos_t handle.
 */
uint64_t odp_cos_to_u64(odp_cos_t hdl);

/**
 * Get printable value for an odp_pmr_t
 *
 * @param hdl          odp_pmr_t handle to be printed
 *
 * @return uint64_t value that can be used to print/display this handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_pmr_t handle.
 */
uint64_t odp_pmr_to_u64(odp_pmr_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
