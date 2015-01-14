/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_CLASSIFY_H_
#define ODP_CLASSIFY_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_packet.h>
#include <odp_queue.h>

/** @defgroup odp_classification ODP CLASSIFICATION
 *  Classification operations.
 *  @{
 */


/**
 * flow signature type, only used for packet metadata field.
 */
typedef uint32_t odp_flowsig_t;

/**
 * This value is returned from odp_cos_create() on failure,
 * May also be used as a sink class of service that
 * results in packets being discarded.
*/
#define ODP_COS_INVALID    ((odp_cos_t)~0)

/** Maximum ClassOfService name length in chars */
#define ODP_COS_NAME_LEN 32

/**
 * Class-of-service packet drop policies
 */
typedef enum odp_cos_drop {
	ODP_COS_DROP_POOL,    /**< Follow buffer pool drop policy */
	ODP_COS_DROP_NEVER,    /**< Never drop, ignoring buffer pool policy */
} odp_drop_e;

/**
 * Packet header field enumeration
 * for fields that may be used to calculate
 * the flow signature, if present in a packet.
 */
typedef enum odp_cos_hdr_flow_fields {
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
} odp_cos_hdr_flow_fields_e;

/**
 * Create a class-of-service
 *
 * @param[in]  name	String intended for debugging purposes.
 *
 * @return		Class of service instance identifier,
 *			or ODP_COS_INVALID on error.
 */
odp_cos_t odp_cos_create(const char *name);

/**
 * Discard a class-of-service along with all its associated resources
 *
 * @param[in]	cos_id	class-of-service instance.
 *
 * @return		0 on success, non-zero on error.
 */
int odp_cos_destroy(odp_cos_t cos_id);

/**
 * Assign a queue for a class-of-service
 *
 * @param[in]	cos_id		class-of-service instance.
 *
 * @param[in]	queue_id	Identifier of a queue where all packets
 *				of this specific class of service
 *				will be enqueued.
 *
 * @return			0 on success, non-zero on error.
 */
int odp_cos_set_queue(odp_cos_t cos_id, odp_queue_t queue_id);

/**
 * Assign packet drop policy for specific class-of-service
 *
 * @param[in]	cos_id		class-of-service instance.
 * @param[in]	drop_policy	Desired packet drop policy for this class.
 *
 * @return			0 on success, non-zero on error.
 *
 * @note Optional.
 */
int odp_cos_set_drop(odp_cos_t cos_id, odp_drop_e drop_policy);

/**
 * Request to override per-port class of service
 * based on Layer-2 priority field if present.
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	num_qos		Number of QoS levels, typically 8.
 * @param[in]	qos_table	Values of the Layer-2 QoS header field.
 * @param[in]	cos_table	Class-of-service assigned to each of the
 *				allowed Layer-2 QOS levels.
 * @return			0 on success, non-zero on error.
 */
int odp_cos_with_l2_priority(odp_pktio_t pktio_in,
			     uint8_t num_qos,
			     uint8_t qos_table[],
			     odp_cos_t cos_table[]);

/**
 * Request to override per-port class of service
 * based on Layer-3 priority field if present.
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	num_qos		Number of allowed Layer-3 QoS levels.
 * @param[in]	qos_table	Values of the Layer-3 QoS header field.
 * @param[in]	cos_table	Class-of-service assigned to each of the
 *				allowed Layer-3 QOS levels.
 * @param[in]	l3_preference	when true, Layer-3 QoS overrides
 *				L2 QoS when present.
 *
 * @return			0 on success, non-zero on error.
 *
 * @note Optional.
 */
int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference);


/**
 * Set of header fields that take part in flow signature hash calculation:
 * bit positions per odp_cos_hdr_flow_fields_e enumeration.
 */
typedef uint16_t odp_cos_flow_set_t;

/**
 * PMR - Packet Matching Rule
 * Up to 32 bit of ternary matching of one of the available header fields
 */
typedef uint32_t odp_pmr_t;

/**
 * Macro for Invalid PMR.
 */
#define    ODP_PMR_INVAL ((odp_pmr_t)~0)

/**
 * Packet Matching Rule field enumeration
 * for fields that may be used to calculate
 * the PMR, if present in a packet.
 */
typedef enum odp_pmr_term {
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

	/** Inner header may repeat above values with this offset */
	ODP_PMR_INNER_HDR_OFF = 32
} odp_pmr_term_e;

/**
 * Create a packet match rule with mask and value
 *
 * @param[in]	term	One of the enumerated values supported
 * @param[in]	val     Value to match against the packet header
 *			in native byte order.
 * @param[in]	mask	Mask to indicate which bits of the header
 *			should be matched ('1') and
 *			which should be ignored ('0')
 * @param[in]	val_sz  Size of the val and mask arguments,
 *			that must match the value size requirement of the
 *			specific term.
 *
 * @return		Handle of the matching rule or ODP_PMR_INVAL on error
 */
odp_pmr_t odp_pmr_create_match(odp_pmr_term_e term,
			       const void *val,
			       const void *mask,
			       uint32_t val_sz);

/**
 * Create a packet match rule with value range
 *
 * @param[in]	term	One of the enumerated values supported
 * @param[in]	val1    Lower bound of the header field range.
 * @param[in]	val2    Upper bound of the header field range.
 * @param[in]	val_sz	Size of the val1 and val2 arguments,
 *			that must match the value size requirement of the
 *			specific term.
 *
 * @return		Handle of the matching rule or ODP_PMR_INVAL on error
 * @note: Range is inclusive [val1..val2].
 */
odp_pmr_t odp_pmr_create_range(odp_pmr_term_e term,
			       const void *val1,
			       const void *val2,
			       uint32_t val_sz);
/**
 * Invalidate a packet match rule and vacate its resources
 *
 * @param[in]	pmr_id	Identifier of the PMR to be destroyed
 *
 * @return		0 on success, non-zero or error.
 */
int odp_pmr_destroy(odp_pmr_t pmr_id);

/**
 * Apply a PMR to a pktio to assign a CoS.
 *
 * @param[in]	pmr_id		PMR to be activated
 * @param[in]	src_pktio	pktio to which this PMR is to be applied
 * @param[in]	dst_cos		CoS to be assigned by this PMR
 *
 * @return			0 on success, non-zero or error.
 */
int odp_pktio_pmr_cos(odp_pmr_t pmr_id,
		      odp_pktio_t src_pktio, odp_cos_t dst_cos);

/**
 * Cascade a PMR to refine packets from one CoS to another.
 *
 * @param[in]	pmr_id		PMR to be activated
 * @param[in]	src_cos		CoS to be filtered
 * @param[in]	dst_cos		CoS to be assigned to packets filtered
 *				from src_cos that match pmr_id.
 *
 * @return			0 on success, non-zero on error.
 */
int odp_cos_pmr_cos(odp_pmr_t pmr_id, odp_cos_t src_cos, odp_cos_t dst_cos);

/**
 * Retrieve packet matcher statistics
 *
 * @param[in]	pmr_id		PMR from which to retrieve the count
 *
 * @return			Current number of matches for a given matcher instance.
 */
signed long odp_pmr_match_count(odp_pmr_t pmr_id);

/**
 * Inquire about matching terms supported by the classifier
 *
 * @return A mask one bit per enumerated term, one for each of op_pmr_term_e
 */
unsigned long long odp_pmr_terms_cap(void);

/**
 * Return the number of packet matching terms available for use
 *
 * @return A number of packet matcher resources available for use.
 */
unsigned odp_pmr_terms_avail(void);

/**
 * Packet Match Type field enumeration
 * for fields that may be used to identify
 * the different PMR match type.
 */
typedef enum odp_pmr_match_type {
		ODP_PMR_MASK,       /**< Match a masked set of bits */
		ODP_PMR_RANGE,      /**< Match an integer range */
	} odp_pmr_match_type_e;

/**
 * Following structure is used to define composite packet matching rules
 * in the form of an array of individual match or range rules.
 * The underlying platform may not support all or any specific combination
 * of value match or range rules, and the application should take care
 * of inspecting the return value when installing such rules, and perform
 * appropriate fallback action.
 */
typedef struct odp_pmr_match_t {
	odp_pmr_match_type_e match_type; /**< Packet Match Type*/
	union {
		struct {
			odp_pmr_term_e  term;
			const void          *val;
			const void          *mask;
			unsigned int         val_sz;
		} mask; /**< Match a masked set of bits */
		struct {
			odp_pmr_term_e  term;
			const void          *val1;
			const void          *val2;
			unsigned int         val_sz;
		} range; /**< Match an integer range */
	};
} odp_pmr_match_t;

/** An opaque handle to a composite packet match rule-set */
typedef uint32_t odp_pmr_set_t;

/**
 * Create a composite packet match rule
 *
 * @param[in]	num_terms	Number of terms in the match rule.
 * @param[in]	terms		Array of num_terms entries, one entry per
 *				term desired.
 * @param[out]	pmr_set_id	Returned handle to the composite rule set.
 *
 * @return			Return value may be a positive number
 *				indicating the number of terms elements
 *				that have been successfully mapped to the
 *				underlying platform classification engine and
 *				may be in the range from 1 to num_terms,
 *				or non-zero for error.
 */
int odp_pmr_match_set_create(int num_terms, odp_pmr_match_t *terms,
			     odp_pmr_set_t *pmr_set_id);

/**
 * Function to delete a composite packet match rule set
 * Depending on the implementation details, destroying a rule-set
 * may not guarantee the availability of hardware resources to create the
 * same or essentially similar rule-set.
 *
 * All of the resources pertaining to the match set associated with the
 * class-of-service will be released, but the class-of-service will
 * remain intact.
 *
 * @param[in]	pmr_set_id	A composite rule-set handle
 *				returned when created.
 *
 * @return			0 on success, non-zero on error.
 */
int odp_pmr_match_set_destroy(odp_pmr_set_t pmr_set_id);

/**
 * Apply a PMR Match Set to a pktio to assign a CoS.
 *
 * @param[in]	pmr_set_id	PMR match set to be activated
 * @param[in]	src_pktio	pktio to which this PMR match
 *				set is to be applied
 * @param[in]	dst_cos		CoS to be assigned by this PMR match set
 *
 * @return			0 on success, non-zero or error.
 */
int odp_pktio_pmr_match_set_cos(odp_pmr_set_t pmr_set_id, odp_pktio_t src_pktio,
				odp_cos_t dst_cos);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
