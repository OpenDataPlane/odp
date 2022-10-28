/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Classification Datamodel
 * Describes the classification internal data model
 */

#ifndef ODP_CLASSIFICATION_DATAMODEL_H_
#define ODP_CLASSIFICATION_DATAMODEL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spinlock.h>
#include <odp/api/classification.h>
#include <odp/api/debug.h>

#include <odp_macros_internal.h>
#include <odp_pool_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_queue_if.h>

#include <protocols/ip.h>

/* Maximum Class Of Service Entry */
#define CLS_COS_MAX_ENTRY		64
/* Invalid CoS index */
#define CLS_COS_IDX_NONE		CLS_COS_MAX_ENTRY
/* Maximum PMR Entry */
#define CLS_PMR_MAX_ENTRY		256
/* Maximum PMR Terms in a PMR Set */
#define CLS_PMRTERM_MAX			8
/* Maximum PMRs attached in PKTIO Level */
#define CLS_PMR_PER_COS_MAX		8
/* L2 Priority Bits */
#define CLS_COS_L2_QOS_BITS		3
/* Max L2 QoS value */
#define CLS_COS_MAX_L2_QOS		(1 << CLS_COS_L2_QOS_BITS)
/* L2 DSCP Bits */
#define CLS_COS_L3_QOS_BITS		6
/* Max L3 QoS Value */
#define CLS_COS_MAX_L3_QOS		(1 << CLS_COS_L3_QOS_BITS)
/* Max PMR Term size */
#define MAX_PMR_TERM_SIZE		16
/* Max queue per Class of service */
#define CLS_COS_QUEUE_MAX		32
/* Max number of implementation created queues */
#define CLS_QUEUE_GROUP_MAX		(CLS_COS_MAX_ENTRY * CLS_COS_QUEUE_MAX)

/* CoS index is stored in odp_packet_hdr_t */
ODP_STATIC_ASSERT(CLS_COS_MAX_ENTRY <= UINT16_MAX, "CoS_does_not_fit_16_bits");

typedef union {
	/* All proto fileds */
	uint32_t all;

	struct {
		uint32_t ipv4:1;
		uint32_t ipv6:1;
		uint32_t udp:1;
		uint32_t tcp:1;
	};
} odp_cls_hash_proto_t;

/*
 * Term and value mapping for a PMR
 */
typedef struct pmr_term_value {
	/* PMR Term */
	odp_cls_pmr_term_t term;

	/* True if range, false if match */
	odp_bool_t range_term;

	union {
		/* Match value and mask */
		struct {
			/* Value to be matched. Arrays are used with custom and
			 * IPv6 address terms. */
			union {
				uint64_t value;
				uint8_t  value_u8[MAX_PMR_TERM_SIZE];
				uint64_t value_u64[2];
			};

			/* Mask for the data to be matched */
			union {
				uint64_t mask;
				uint8_t  mask_u8[MAX_PMR_TERM_SIZE];
				uint64_t mask_u64[2];
			};

		} match;

		/* Range values */
		struct {
			/* Start value of the range */
			union {
				uint64_t start;
				uint8_t  start_u8[MAX_PMR_TERM_SIZE];
				uint64_t start_u64[2];
			};

			/* End value of the range */
			union {
				uint64_t end;
				uint8_t  end_u8[MAX_PMR_TERM_SIZE];
				uint64_t end_u64[2];
			};

		} range;

	};

	/* Offset used with custom PMR */
	uint32_t offset;

	/* Size of the value to be matched */
	uint32_t val_sz;

} pmr_term_value_t;

/*
Class Of Service
*/
typedef struct ODP_ALIGNED_CACHE cos_s {
	uint32_t valid;			/* validity Flag */
	odp_atomic_u32_t num_rule;	/* num of PMRs attached with this CoS */
	struct pmr_s *pmr[CLS_PMR_PER_COS_MAX];	/* Chained PMR */
	struct cos_s *linked_cos[CLS_PMR_PER_COS_MAX]; /* Chained CoS with PMR*/
	odp_bool_t stats_enable;
	odp_cos_action_t action;	/* Action */
	odp_queue_t queue;		/* Associated Queue */
	uint32_t num_queue;
	odp_pool_t pool;		/* Associated Buffer pool */
	uint8_t index;
	bool queue_group;
	odp_cls_hash_proto_t hash_proto;
	odp_pktin_vector_config_t vector;	/* Packet vector config */
#if ODP_DEPRECATED_API
	odp_cls_drop_t drop_policy;	/* Associated Drop Policy */
#endif
	size_t headroom;		/* Headroom for this CoS */
	odp_spinlock_t lock;		/* cos lock */
	odp_queue_param_t queue_param;
	char name[ODP_COS_NAME_LEN];	/* name */
	struct {
		odp_atomic_u64_t discards;
		odp_atomic_u64_t packets;
	} stats, queue_stats[CLS_COS_QUEUE_MAX];
} cos_t;

/* Pattern Matching Rule */
typedef struct ODP_ALIGNED_CACHE pmr_s {
	uint32_t valid;			/* Validity Flag */
	uint32_t num_pmr;		/* num of PMR Term Values*/
	uint16_t mark;
	pmr_term_value_t  pmr_term_value[CLS_PMRTERM_MAX];
			/* List of associated PMR Terms */
	odp_spinlock_t lock;		/* pmr lock*/
	cos_t *src_cos;			/* source CoS where PMR is attached */
} pmr_t;

typedef struct ODP_ALIGNED_CACHE {
	odp_queue_t queue[CLS_QUEUE_GROUP_MAX];
} _cls_queue_grp_tbl_t;

/**
L2 QoS and CoS Map

This structure holds the mapping between L2 QoS value and
corresponding cos_t object
**/
typedef struct pmr_l2_cos {
	odp_spinlock_t lock;	/* pmr_l2_cos lock */
	cos_t *cos[CLS_COS_MAX_L2_QOS];	/* Array of CoS objects */
} pmr_l2_cos_t;

/**
L3 QoS and CoS Map

This structure holds the mapping between L3 QoS value and
corresponding cos_t object
**/
typedef struct pmr_l3_cos {
	odp_spinlock_t lock;	/* pmr_l3_cos lock */
	cos_t *cos[CLS_COS_MAX_L3_QOS];	/* Array of CoS objects */
} pmr_l3_cos_t;

/**
Linux Generic Classifier

This structure is stored in pktio_entry and holds all
the classifier configuration value.
**/
typedef struct classifier {
	cos_t *error_cos;		/* Associated Error CoS */
	cos_t *default_cos;		/* Associated Default CoS */
	uint32_t l3_precedence;		/* L3 QoS precedence */
	pmr_l2_cos_t l2_cos_table;	/* L2 QoS-CoS table map */
	pmr_l3_cos_t l3_cos_table;	/* L3 Qos-CoS table map */
	size_t headroom;		/* Pktio Headroom */
	size_t skip;			/* Pktio Skip Offset */
} classifier_t;

/**
Class of Service Table
**/
typedef struct odp_cos_table {
	cos_t cos_entry[CLS_COS_MAX_ENTRY];
} cos_tbl_t;

/**
PMR table
**/
typedef struct pmr_tbl {
	pmr_t pmr[CLS_PMR_MAX_ENTRY];
} pmr_tbl_t;

/**
Classifier global data
**/
typedef struct cls_global_t {
	cos_tbl_t cos_tbl;
	pmr_tbl_t pmr_tbl;
	_cls_queue_grp_tbl_t queue_grp_tbl;
	odp_shm_t shm;

} cls_global_t;

#ifdef __cplusplus
}
#endif
#endif
