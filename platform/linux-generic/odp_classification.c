/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/classification.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/debug.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>
#include <odp_classification_internal.h>
#include <odp/api/shared_memory.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/ipsec.h>
#include <protocols/udp.h>
#include <protocols/tcp.h>
#include <protocols/thash.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <odp/api/spinlock.h>

#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a)	odp_spinlock_init(a)

static cos_tbl_t *cos_tbl;
static pmr_tbl_t	*pmr_tbl;
static _cls_queue_grp_tbl_t *queue_grp_tbl;

typedef struct cls_global_t {
	cos_tbl_t cos_tbl;
	pmr_tbl_t pmr_tbl;
	_cls_queue_grp_tbl_t queue_grp_tbl;
	odp_shm_t shm;

} cls_global_t;

static cls_global_t *cls_global;

static const rss_key default_rss = {
	.u8 = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
	}
};

static inline uint32_t _odp_cos_to_ndx(odp_cos_t cos)
{
	return _odp_typeval(cos) - 1;
}

static inline odp_cos_t _odp_cos_from_ndx(uint32_t ndx)
{
	return _odp_cast_scalar(odp_cos_t, ndx + 1);
}

static inline uint32_t _odp_pmr_to_ndx(odp_pmr_t pmr)
{
	return _odp_typeval(pmr) - 1;
}

static inline odp_pmr_t _odp_pmr_from_ndx(uint32_t ndx)
{
	return _odp_cast_scalar(odp_pmr_t, ndx + 1);
}

static
cos_t *get_cos_entry_internal(odp_cos_t cos)
{
	return &cos_tbl->cos_entry[_odp_cos_to_ndx(cos)];
}

static
pmr_t *get_pmr_entry_internal(odp_pmr_t pmr)
{
	return &pmr_tbl->pmr[_odp_pmr_to_ndx(pmr)];
}

int _odp_classification_init_global(void)
{
	odp_shm_t shm;
	int i;

	shm = odp_shm_reserve("_odp_cls_global", sizeof(cls_global_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	cls_global = odp_shm_addr(shm);
	memset(cls_global, 0, sizeof(cls_global_t));

	cls_global->shm = shm;
	cos_tbl       = &cls_global->cos_tbl;
	pmr_tbl       = &cls_global->pmr_tbl;
	queue_grp_tbl = &cls_global->queue_grp_tbl;

	for (i = 0; i < CLS_COS_MAX_ENTRY; i++) {
		/* init locks */
		cos_t *cos = get_cos_entry_internal(_odp_cos_from_ndx(i));
		LOCK_INIT(&cos->s.lock);
	}

	for (i = 0; i < CLS_PMR_MAX_ENTRY; i++) {
		/* init locks */
		pmr_t *pmr = get_pmr_entry_internal(_odp_pmr_from_ndx(i));
		LOCK_INIT(&pmr->s.lock);
	}

	return 0;
}

int _odp_classification_term_global(void)
{
	if (cls_global && odp_shm_free(cls_global->shm)) {
		ODP_ERR("shm free failed\n");
		return -1;
	}

	return 0;
}

void odp_cls_cos_param_init(odp_cls_cos_param_t *param)
{
	param->queue = ODP_QUEUE_INVALID;
	param->pool = ODP_POOL_INVALID;
	param->drop_policy = ODP_COS_DROP_NEVER;
	param->num_queue = 1;
	odp_queue_param_init(&param->queue_param);
}

void odp_cls_pmr_param_init(odp_pmr_param_t *param)
{
	memset(param, 0, sizeof(odp_pmr_param_t));
}

int odp_cls_capability(odp_cls_capability_t *capability)
{
	unsigned count = 0;

	for (int i = 0; i < CLS_PMR_MAX_ENTRY; i++)
		if (!pmr_tbl->pmr[i].s.valid)
			count++;

	capability->max_pmr_terms = CLS_PMR_MAX_ENTRY;
	capability->available_pmr_terms = count;
	capability->max_cos = CLS_COS_MAX_ENTRY;
	capability->pmr_range_supported = false;
	capability->supported_terms.all_bits = 0;
	capability->supported_terms.bit.len = 1;
	capability->supported_terms.bit.ethtype_0 = 1;
	capability->supported_terms.bit.ethtype_x = 1;
	capability->supported_terms.bit.vlan_id_0 = 1;
	capability->supported_terms.bit.vlan_id_x = 1;
	capability->supported_terms.bit.dmac = 1;
	capability->supported_terms.bit.ip_proto = 1;
	capability->supported_terms.bit.udp_dport = 1;
	capability->supported_terms.bit.udp_sport = 1;
	capability->supported_terms.bit.tcp_dport = 1;
	capability->supported_terms.bit.tcp_sport = 1;
	capability->supported_terms.bit.sip_addr = 1;
	capability->supported_terms.bit.dip_addr = 1;
	capability->supported_terms.bit.sip6_addr = 1;
	capability->supported_terms.bit.dip6_addr = 1;
	capability->random_early_detection = ODP_SUPPORT_NO;
	capability->back_pressure = ODP_SUPPORT_NO;
	capability->threshold_red.all_bits = 0;
	capability->threshold_bp.all_bits = 0;
	capability->max_hash_queues = CLS_COS_QUEUE_MAX;
	return 0;
}

static void _odp_cls_update_hash_proto(cos_t *cos,
				       odp_pktin_hash_proto_t hash_proto)
{
	if (hash_proto.proto.ipv4 || hash_proto.proto.ipv4_tcp ||
	    hash_proto.proto.ipv4_udp)
		cos->s.hash_proto.ipv4 = 1;
	if (hash_proto.proto.ipv6 || hash_proto.proto.ipv6_tcp ||
	    hash_proto.proto.ipv6_udp)
		cos->s.hash_proto.ipv6 = 1;
	if (hash_proto.proto.ipv4_tcp || hash_proto.proto.ipv6_tcp)
		cos->s.hash_proto.tcp = 1;
	if (hash_proto.proto.ipv4_udp || hash_proto.proto.ipv6_udp)
		cos->s.hash_proto.udp = 1;
}

static inline void _cls_queue_unwind(uint32_t tbl_index, uint32_t j)
{
	while (j > 0)
		odp_queue_destroy(queue_grp_tbl->s.queue[tbl_index + --j]);
}

odp_cos_t odp_cls_cos_create(const char *name, odp_cls_cos_param_t *param)
{
	uint32_t i, j;
	odp_queue_t queue;
	odp_cls_drop_t drop_policy;
	cos_t *cos;
	uint32_t tbl_index;

	/* num_queue should not be zero */
	if (param->num_queue > CLS_COS_QUEUE_MAX || param->num_queue < 1)
		return ODP_COS_INVALID;

	drop_policy = param->drop_policy;

	for (i = 0; i < CLS_COS_MAX_ENTRY; i++) {
		cos = &cos_tbl->cos_entry[i];
		LOCK(&cos->s.lock);
		if (0 == cos->s.valid) {
			char *cos_name = cos->s.name;

			if (name == NULL) {
				cos_name[0] = 0;
			} else {
				strncpy(cos_name, name, ODP_COS_NAME_LEN - 1);
				cos_name[ODP_COS_NAME_LEN - 1] = 0;
			}
			for (j = 0; j < CLS_PMR_PER_COS_MAX; j++) {
				cos->s.pmr[j] = NULL;
				cos->s.linked_cos[j] = NULL;
			}

			cos->s.num_queue = param->num_queue;

			if (param->num_queue > 1) {
				odp_queue_param_init(&cos->s.queue_param);
				cos->s.queue_group = true;
				cos->s.queue = ODP_QUEUE_INVALID;
				_odp_cls_update_hash_proto(cos,
							   param->hash_proto);
				tbl_index = i * CLS_COS_QUEUE_MAX;
				for (j = 0; j < param->num_queue; j++) {
					queue = odp_queue_create(NULL, &cos->s.
								 queue_param);
					if (queue == ODP_QUEUE_INVALID) {
						/* unwind the queues */
						_cls_queue_unwind(tbl_index, j);
						UNLOCK(&cos->s.lock);
						return ODP_COS_INVALID;
					}
					queue_grp_tbl->s.queue[tbl_index + j] =
							queue;
				}

			} else {
				cos->s.queue = param->queue;
			}

			cos->s.pool = param->pool;
			cos->s.headroom = 0;
			cos->s.valid = 1;
			cos->s.drop_policy = drop_policy;
			odp_atomic_init_u32(&cos->s.num_rule, 0);
			cos->s.index = i;
			UNLOCK(&cos->s.lock);
			return _odp_cos_from_ndx(i);
		}
		UNLOCK(&cos->s.lock);
	}

	ODP_ERR("CLS_COS_MAX_ENTRY reached\n");
	return ODP_COS_INVALID;
}

/*
 * Allocate an odp_pmr_t Handle
 */
static
odp_pmr_t alloc_pmr(pmr_t **pmr)
{
	int i;

	for (i = 0; i < CLS_PMR_MAX_ENTRY; i++) {
		LOCK(&pmr_tbl->pmr[i].s.lock);
		if (0 == pmr_tbl->pmr[i].s.valid) {
			pmr_tbl->pmr[i].s.valid = 1;
			odp_atomic_init_u32(&pmr_tbl->pmr[i].s.count, 0);
			pmr_tbl->pmr[i].s.num_pmr = 0;
			*pmr = &pmr_tbl->pmr[i];
			/* return as locked */
			return _odp_pmr_from_ndx(i);
		}
		UNLOCK(&pmr_tbl->pmr[i].s.lock);
	}
	ODP_ERR("CLS_PMR_MAX_ENTRY reached\n");
	return ODP_PMR_INVALID;
}

static
cos_t *get_cos_entry(odp_cos_t cos)
{
	uint32_t cos_id = _odp_cos_to_ndx(cos);

	if (cos_id >= CLS_COS_MAX_ENTRY || cos == ODP_COS_INVALID)
		return NULL;
	if (cos_tbl->cos_entry[cos_id].s.valid == 0)
		return NULL;
	return &cos_tbl->cos_entry[cos_id];
}

static
pmr_t *get_pmr_entry(odp_pmr_t pmr)
{
	uint32_t pmr_id = _odp_pmr_to_ndx(pmr);

	if (pmr_id >= CLS_PMR_MAX_ENTRY ||
	    pmr == ODP_PMR_INVALID)
		return NULL;
	if (pmr_tbl->pmr[pmr_id].s.valid == 0)
		return NULL;
	return &pmr_tbl->pmr[pmr_id];
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (NULL == cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	cos->s.valid = 0;
	return 0;
}

int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	if (cos->s.num_queue != 1) {
		ODP_ERR("Hashing enabled, cannot set queue\n");
		return -1;
	}

	/* Locking is not required as intermittent stale
	data during CoS modification is acceptable*/
	cos->s.queue = queue_id;
	return 0;
}

odp_queue_t odp_cos_queue(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_QUEUE_INVALID;
	}

	return cos->s.queue;
}

uint32_t odp_cls_cos_num_queue(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return 0;
	}

	return cos->s.num_queue;
}

uint32_t odp_cls_cos_queues(odp_cos_t cos_id, odp_queue_t queue[],
			    uint32_t num)
{
	uint32_t num_queues;
	cos_t *cos;
	uint32_t tbl_index;
	uint32_t i;

	cos  = get_cos_entry(cos_id);
	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return 0;
	}

	if (cos->s.num_queue == 1) {
		if (num == 0)
			return 1;

		queue[0] = cos->s.queue;
		return 1;
	}

	if (num < cos->s.num_queue)
		num_queues = num;
	else
		num_queues = cos->s.num_queue;

	tbl_index = cos->s.index * CLS_COS_QUEUE_MAX;
	for (i = 0; i < num_queues; i++)
		queue[i] = queue_grp_tbl->s.queue[tbl_index + i];

	return num_queues;
}

int odp_cos_drop_set(odp_cos_t cos_id, odp_cls_drop_t drop_policy)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	/*Drop policy is not supported in v1.0*/
	cos->s.drop_policy = drop_policy;
	return 0;
}

odp_cls_drop_t odp_cos_drop(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	return cos->s.drop_policy;
}

int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	cos = get_cos_entry(default_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	entry->s.cls.default_cos = cos;
	return 0;
}

int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}

	cos = get_cos_entry(error_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	entry->s.cls.error_cos = cos;
	return 0;
}

int odp_pktio_skip_set(odp_pktio_t pktio_in, uint32_t offset)
{
	pktio_entry_t *entry = get_pktio_entry(pktio_in);

	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}

	entry->s.cls.skip = offset;
	return 0;
}

int odp_pktio_headroom_set(odp_pktio_t pktio_in, uint32_t headroom)
{
	pktio_entry_t *entry = get_pktio_entry(pktio_in);

	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	entry->s.cls.headroom = headroom;
	return 0;
}

int odp_cos_with_l2_priority(odp_pktio_t pktio_in,
			     uint8_t num_qos,
			     uint8_t qos_table[],
			     odp_cos_t cos_table[])
{
	pmr_l2_cos_t *l2_cos;
	uint32_t i;
	cos_t *cos;
	pktio_entry_t *entry = get_pktio_entry(pktio_in);

	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	l2_cos = &entry->s.cls.l2_cos_table;

	LOCK(&l2_cos->lock);
	/* Update the L2 QoS table*/
	for (i = 0; i < num_qos; i++) {
		cos = get_cos_entry(cos_table[i]);
		if (cos != NULL) {
			if (CLS_COS_MAX_L2_QOS > qos_table[i])
				l2_cos->cos[qos_table[i]] = cos;
		}
	}
	UNLOCK(&l2_cos->lock);
	return 0;
}

int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference)
{
	pmr_l3_cos_t *l3_cos;
	uint32_t i;
	pktio_entry_t *entry = get_pktio_entry(pktio_in);
	cos_t *cos;

	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}

	entry->s.cls.l3_precedence = l3_preference;
	l3_cos = &entry->s.cls.l3_cos_table;

	LOCK(&l3_cos->lock);
	/* Update the L3 QoS table*/
	for (i = 0; i < num_qos; i++) {
		cos = get_cos_entry(cos_table[i]);
		if (cos != NULL) {
			if (CLS_COS_MAX_L3_QOS > qos_table[i])
				l3_cos->cos[qos_table[i]] = cos;
		}
	}
	UNLOCK(&l3_cos->lock);
	return 0;
}

static int odp_pmr_create_term(pmr_term_value_t *value,
			       const odp_pmr_param_t *param)
{
	value->term = param->term;
	value->range_term = param->range_term;
	uint8_t i;

	switch (value->term) {
	case ODP_PMR_SIP6_ADDR:
	case ODP_PMR_DIP6_ADDR:
	if (!value->range_term) {
		memset(value->match_ipv6.addr.u8, 0, 16);
		memset(value->match_ipv6.mask.u8, 0, 16);
		memcpy(&value->match_ipv6.addr.u8, param->match.value,
		       param->val_sz);
		memcpy(&value->match_ipv6.mask.u8, param->match.mask,
		       param->val_sz);
		for (i = 0; i < 2; i++)
			value->match_ipv6.addr.u64[i] &=
				value->match_ipv6.mask.u64[i];
	} else {
		memset(value->range_ipv6.addr_start.u8, 0, 16);
		memset(value->range_ipv6.addr_end.u8, 0, 16);
		memcpy(&value->range_ipv6.addr_start.u8, param->range.val_start,
		       param->val_sz);
		memcpy(&value->range_ipv6.addr_end.u8, param->range.val_end,
		       param->val_sz);
	}

	break;
	default:
	if (!value->range_term) {
		value->match.value = 0;
		value->match.mask = 0;
		memcpy(&value->match.value, param->match.value, param->val_sz);
		memcpy(&value->match.mask, param->match.mask, param->val_sz);
		value->match.value &= value->match.mask;
	} else {
		value->range.val_start = 0;
		value->range.val_end = 0;
		memcpy(&value->range.val_start, param->range.val_start,
		       param->val_sz);
		memcpy(&value->range.val_end, param->range.val_end,
		       param->val_sz);
	}
	}
	value->offset = param->offset;
	value->val_sz = param->val_sz;
	return 0;
}

int odp_cls_pmr_destroy(odp_pmr_t pmr_id)
{
	cos_t *src_cos;
	uint32_t loc;
	pmr_t *pmr;
	uint8_t i;

	pmr = get_pmr_entry(pmr_id);
	if (pmr == NULL || pmr->s.src_cos == NULL)
		return -1;

	src_cos = pmr->s.src_cos;
	LOCK(&src_cos->s.lock);
	loc = odp_atomic_load_u32(&src_cos->s.num_rule);
	if (loc == 0)
		goto no_rule;
	loc -= 1;
	for (i = 0; i <= loc; i++)
		if (src_cos->s.pmr[i] == pmr) {
			src_cos->s.pmr[i] = src_cos->s.pmr[loc];
			src_cos->s.linked_cos[i] = src_cos->s.linked_cos[loc];
		}
	odp_atomic_dec_u32(&src_cos->s.num_rule);

no_rule:
	pmr->s.valid = 0;
	UNLOCK(&src_cos->s.lock);
	return 0;
}

odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
			     odp_cos_t src_cos, odp_cos_t dst_cos)
{
	pmr_t *pmr;
	int i;
	odp_pmr_t id;
	int val_sz;
	uint32_t loc;
	cos_t *cos_src = get_cos_entry(src_cos);
	cos_t *cos_dst = get_cos_entry(dst_cos);

	if (NULL == cos_src || NULL == cos_dst) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_PMR_INVALID;
	}

	if (num_terms > CLS_PMRTERM_MAX) {
		ODP_ERR("no of terms greater than supported CLS_PMRTERM_MAX\n");
		return ODP_PMR_INVALID;
	}

	if (CLS_PMR_PER_COS_MAX == odp_atomic_load_u32(&cos_src->s.num_rule))
		return ODP_PMR_INVALID;

	id = alloc_pmr(&pmr);
	/*if alloc_pmr is successful it returns with the acquired lock*/
	if (id == ODP_PMR_INVALID)
		return id;

	pmr->s.num_pmr = num_terms;
	for (i = 0; i < num_terms; i++) {
		val_sz = terms[i].val_sz;
		if (val_sz > CLS_PMR_TERM_BYTES_MAX) {
			pmr->s.valid = 0;
			return ODP_PMR_INVALID;
		}
		if (0 > odp_pmr_create_term(&pmr->s.pmr_term_value[i],
					    &terms[i])) {
			UNLOCK(&pmr->s.lock);
			return ODP_PMR_INVALID;
		}
	}

	loc = odp_atomic_fetch_inc_u32(&cos_src->s.num_rule);
	cos_src->s.pmr[loc] = pmr;
	cos_src->s.linked_cos[loc] = cos_dst;
	pmr->s.src_cos = cos_src;

	UNLOCK(&pmr->s.lock);
	return id;
}

int odp_cls_cos_pool_set(odp_cos_t cos_id, odp_pool_t pool)
{
	cos_t *cos;

	cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	cos->s.pool = pool;

	return 0;
}

odp_pool_t odp_cls_cos_pool(odp_cos_t cos_id)
{
	cos_t *cos;

	cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_POOL_INVALID;
	}

	return cos->s.pool;
}

static inline int verify_pmr_packet_len(odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	if (term_value->match.value == (packet_len(pkt_hdr) &
				     term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ip_proto(const uint8_t *pkt_addr,
				      odp_packet_hdr_t *pkt_hdr,
				      pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint8_t proto;

	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	proto = ip->proto;
	if (term_value->match.value == (proto & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_saddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint32_t ipaddr;

	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	ipaddr = odp_be_to_cpu_32(ip->src_addr);
	if (term_value->match.value == (ipaddr & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_daddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint32_t ipaddr;

	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	ipaddr = odp_be_to_cpu_32(ip->dst_addr);
	if (term_value->match.value == (ipaddr & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_tcp_sport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t sport;
	const _odp_tcphdr_t *tcp;

	if (!pkt_hdr->p.input_flags.tcp)
		return 0;
	tcp = (const _odp_tcphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	sport = odp_be_to_cpu_16(tcp->src_port);
	if (term_value->match.value == (sport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_tcp_dport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t dport;
	const _odp_tcphdr_t *tcp;

	if (!pkt_hdr->p.input_flags.tcp)
		return 0;
	tcp = (const _odp_tcphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	dport = odp_be_to_cpu_16(tcp->dst_port);
	if (term_value->match.value == (dport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_udp_dport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t dport;
	const _odp_udphdr_t *udp;

	if (!pkt_hdr->p.input_flags.udp)
		return 0;
	udp = (const _odp_udphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	dport = odp_be_to_cpu_16(udp->dst_port);
	if (term_value->match.value == (dport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_udp_sport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t sport;
	const _odp_udphdr_t *udp;

	if (!pkt_hdr->p.input_flags.udp)
		return 0;
	udp = (const _odp_udphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	sport = odp_be_to_cpu_16(udp->src_port);
	if (term_value->match.value == (sport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_dmac(const uint8_t *pkt_addr,
				  odp_packet_hdr_t *pkt_hdr,
				  pmr_term_value_t *term_value)
{
	uint64_t dmac = 0;
	uint64_t dmac_be = 0;
	const _odp_ethhdr_t *eth;

	if (!packet_hdr_has_eth(pkt_hdr))
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	memcpy(&dmac_be, eth->dst.addr, _ODP_ETHADDR_LEN);
	dmac = odp_be_to_cpu_64(dmac_be);
	/* since we are converting a 48 bit ethernet address from BE to cpu
	format using odp_be_to_cpu_64() the last 16 bits needs to be right
	shifted */
	if (dmac_be != dmac)
		dmac = dmac >> (64 - (_ODP_ETHADDR_LEN * 8));

	if (term_value->match.value == (dmac & term_value->match.mask))
		return 1;
	return 0;
}

static inline int verify_pmr_ipv6_saddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv6hdr_t *ipv6;
	uint64_t addr[2];

	if (!packet_hdr_has_ipv6(pkt_hdr))
		return 0;

	ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);

	addr[0] = ipv6->src_addr.u64[0];
	addr[1] = ipv6->src_addr.u64[1];

	/* 128 bit address is processed as two 64 bit value
	* for bitwise AND operation */
	addr[0] = addr[0] & term_value->match_ipv6.mask.u64[0];
	addr[1] = addr[1] & term_value->match_ipv6.mask.u64[1];

	if (!memcmp(addr, term_value->match_ipv6.addr.u8, _ODP_IPV6ADDR_LEN))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv6_daddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv6hdr_t *ipv6;
	uint64_t addr[2];

	if (!packet_hdr_has_ipv6(pkt_hdr))
		return 0;
	ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	addr[0] = ipv6->dst_addr.u64[0];
	addr[1] = ipv6->dst_addr.u64[1];

	/* 128 bit address is processed as two 64 bit value
	* for bitwise AND operation */
	addr[0] = addr[0] & term_value->match_ipv6.mask.u64[0];
	addr[1] = addr[1] & term_value->match_ipv6.mask.u64[1];

	if (!memcmp(addr, term_value->match_ipv6.addr.u8, _ODP_IPV6ADDR_LEN))
		return 1;

	return 0;
}

static inline int verify_pmr_vlan_id_0(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t tci;
	uint16_t vlan_id;

	if (!packet_hdr_has_eth(pkt_hdr) || !pkt_hdr->p.input_flags.vlan)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);
	tci = odp_be_to_cpu_16(vlan->tci);
	vlan_id = tci & 0x0fff;

	if (term_value->match.value == (vlan_id & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_vlan_id_x(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t tci;
	uint16_t vlan_id;

	if (!pkt_hdr->p.input_flags.vlan && !pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);

	if (pkt_hdr->p.input_flags.vlan_qinq)
		vlan++;

	tci = odp_be_to_cpu_16(vlan->tci);
	vlan_id = tci & 0x0fff;

	if (term_value->match.value == (vlan_id & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipsec_spi(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint32_t spi;

	pkt_addr += pkt_hdr->p.l4_offset;

	if (pkt_hdr->p.input_flags.ipsec_ah) {
		const _odp_ahhdr_t *ahhdr = (const _odp_ahhdr_t *)pkt_addr;

		spi = odp_be_to_cpu_32(ahhdr->spi);
	} else if (pkt_hdr->p.input_flags.ipsec_esp) {
		const _odp_esphdr_t *esphdr = (const _odp_esphdr_t *)pkt_addr;

		spi = odp_be_to_cpu_32(esphdr->spi);
	} else {
		return 0;
	}

	if (term_value->match.value == (spi & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ld_vni(const uint8_t *pkt_addr ODP_UNUSED,
				    odp_packet_hdr_t *pkt_hdr ODP_UNUSED,
				    pmr_term_value_t *term_value ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static inline int verify_pmr_custom_frame(const uint8_t *pkt_addr,
					  odp_packet_hdr_t *pkt_hdr,
					  pmr_term_value_t *term_value)
{
	uint64_t val = 0;
	uint32_t offset = term_value->offset;
	uint32_t val_sz = term_value->val_sz;

	ODP_ASSERT(val_sz <= CLS_PMR_TERM_BYTES_MAX);

	if (packet_len(pkt_hdr) <= offset + val_sz)
		return 0;

	memcpy(&val, pkt_addr + offset, val_sz);
	if (term_value->match.value == (val & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_eth_type_0(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	uint16_t ethtype;

	if (!packet_hdr_has_eth(pkt_hdr))
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	ethtype = odp_be_to_cpu_16(eth->type);

	if (term_value->match.value == (ethtype & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_eth_type_x(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	uint16_t ethtype;
	const _odp_vlanhdr_t *vlan;

	if (!pkt_hdr->p.input_flags.vlan && !pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);

	if (pkt_hdr->p.input_flags.vlan_qinq)
		vlan++;

	ethtype = odp_be_to_cpu_16(vlan->type);

	if (term_value->match.value == (ethtype & term_value->match.mask))
		return 1;

	return 0;
}

/*
 * This function goes through each PMR_TERM value in pmr_t structure and calls
 * verification function for each term.Returns 1 if PMR matches or 0 otherwise.
 */
static int verify_pmr(pmr_t *pmr, const uint8_t *pkt_addr,
		      odp_packet_hdr_t *pkt_hdr)
{
	int pmr_failure = 0;
	int num_pmr;
	int i;
	pmr_term_value_t *term_value;

	/* Locking is not required as PMR rules for in-flight packets
	delivery during a PMR change is indeterminate*/

	if (!pmr->s.valid)
		return 0;
	num_pmr = pmr->s.num_pmr;

	/* Iterate through list of PMR Term values in a pmr_t */
	for (i = 0; i < num_pmr; i++) {
		term_value = &pmr->s.pmr_term_value[i];
		switch (term_value->term) {
		case ODP_PMR_LEN:
			if (!verify_pmr_packet_len(pkt_hdr, term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_ETHTYPE_0:
			if (!verify_pmr_eth_type_0(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_ETHTYPE_X:
			if (!verify_pmr_eth_type_x(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_VLAN_ID_0:
			if (!verify_pmr_vlan_id_0(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_VLAN_ID_X:
			if (!verify_pmr_vlan_id_x(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_DMAC:
			if (!verify_pmr_dmac(pkt_addr, pkt_hdr,
					     term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_IPPROTO:
			if (!verify_pmr_ip_proto(pkt_addr, pkt_hdr,
						 term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_UDP_DPORT:
			if (!verify_pmr_udp_dport(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_TCP_DPORT:
			if (!verify_pmr_tcp_dport(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_UDP_SPORT:
			if (!verify_pmr_udp_sport(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_TCP_SPORT:
			if (!verify_pmr_tcp_sport(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_SIP_ADDR:
			if (!verify_pmr_ipv4_saddr(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_DIP_ADDR:
			if (!verify_pmr_ipv4_daddr(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_SIP6_ADDR:
			if (!verify_pmr_ipv6_saddr(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_DIP6_ADDR:
			if (!verify_pmr_ipv6_daddr(pkt_addr, pkt_hdr,
						   term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_IPSEC_SPI:
			if (!verify_pmr_ipsec_spi(pkt_addr, pkt_hdr,
						  term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_LD_VNI:
			if (!verify_pmr_ld_vni(pkt_addr, pkt_hdr,
					       term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_CUSTOM_FRAME:
			if (!verify_pmr_custom_frame(pkt_addr, pkt_hdr,
						     term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_INNER_HDR_OFF:
			break;
		default:
			pmr_failure = 1;
			break;
		}

		if (pmr_failure)
			return false;
	}
	odp_atomic_inc_u32(&pmr->s.count);
	return true;
}

/*
 * Match a PMR chain with a Packet and return matching CoS
 * This function gets called recursively to check the chained PMR Term value
 * with the packet.
 */
static
cos_t *match_pmr_cos(cos_t *cos, const uint8_t *pkt_addr, pmr_t *pmr,
		     odp_packet_hdr_t *hdr)
{
	cos_t *retcos;
	uint32_t i;

	retcos  = NULL;

	if (cos == NULL || pmr == NULL)
		return NULL;

	if (!cos->s.valid)
		return NULL;

	if (verify_pmr(pmr, pkt_addr, hdr)) {
		/** This gets called recursively to check all the PMRs in
		 * a PMR chain */
		if (0 == odp_atomic_load_u32(&cos->s.num_rule))
			return cos;

		for (i = 0; i < odp_atomic_load_u32(&cos->s.num_rule); i++) {
			retcos = match_pmr_cos(cos->s.linked_cos[i], pkt_addr,
					       cos->s.pmr[i], hdr);
			if (!retcos)
				return cos;
		}
	}
	return retcos;
}

int pktio_classifier_init(pktio_entry_t *entry)
{
	classifier_t *cls;

	/* classifier lock should be acquired by the calling function */
	if (entry == NULL)
		return -1;
	cls = &entry->s.cls;
	cls->error_cos = NULL;
	cls->default_cos = NULL;
	cls->headroom = 0;
	cls->skip = 0;

	return 0;
}

static
cos_t *match_qos_cos(pktio_entry_t *entry, const uint8_t *pkt_addr,
		     odp_packet_hdr_t *hdr);

/**
Select a CoS for the given Packet based on pktio

This function will call all the PMRs associated with a pktio for
a given packet and will return the matched COS object.
This function will check PMR, L2 and L3 QoS COS object associated
with the PKTIO interface.

Returns the default cos if the packet does not match any PMR
Returns the error_cos if the packet has an error
**/
static inline cos_t *cls_select_cos(pktio_entry_t *entry,
				    const uint8_t *pkt_addr,
				    odp_packet_hdr_t *pkt_hdr)
{
	pmr_t *pmr;
	cos_t *cos;
	cos_t *default_cos;
	uint32_t i;
	classifier_t *cls;

	cls = &entry->s.cls;
	default_cos = cls->default_cos;

	/* Return error cos for error packet */
	if (pkt_hdr->p.flags.all.error)
		return cls->error_cos;
	/* Calls all the PMRs attached at the PKTIO level*/
	for (i = 0; i < odp_atomic_load_u32(&default_cos->s.num_rule); i++) {
		pmr = default_cos->s.pmr[i];
		cos = default_cos->s.linked_cos[i];
		cos = match_pmr_cos(cos, pkt_addr, pmr, pkt_hdr);
		if (cos)
			return cos;
	}

	cos = match_qos_cos(entry, pkt_addr, pkt_hdr);
	if (cos)
		return cos;

	return cls->default_cos;
}

static uint32_t packet_rss_hash(odp_packet_hdr_t *pkt_hdr,
				odp_cls_hash_proto_t hash_proto,
				const uint8_t *base);

/**
 * Classify packet
 *
 * @param pktio_entry	Ingress pktio
 * @param base		Packet data
 * @param pkt_len	Packet length
 * @param seg_leg	Segment length
 * @param pool[out]	Packet pool
 * @param pkt_hdr[out]	Packet header
 *
 * @retval 0 on success
 * @retval -EFAULT Bug
 * @retval -EINVAL Config error
 *
 * @note *base is not released
 */
int cls_classify_packet(pktio_entry_t *entry, const uint8_t *base,
			uint16_t pkt_len, uint32_t seg_len, odp_pool_t *pool,
			odp_packet_hdr_t *pkt_hdr, odp_bool_t parse)
{
	cos_t *cos;
	uint32_t tbl_index;
	uint32_t hash;

	if (parse) {
		packet_parse_reset(pkt_hdr);
		packet_set_len(pkt_hdr, pkt_len);

		packet_parse_common(&pkt_hdr->p, base, pkt_len, seg_len,
				    ODP_PROTO_LAYER_ALL,
				    entry->s.in_chksums);
	}
	cos = cls_select_cos(entry, base, pkt_hdr);

	if (cos == NULL)
		return -EINVAL;

	if (cos->s.queue == ODP_QUEUE_INVALID && cos->s.num_queue == 1)
		return -EFAULT;

	if (cos->s.pool == ODP_POOL_INVALID)
		return -EFAULT;

	*pool = cos->s.pool;
	pkt_hdr->p.input_flags.dst_queue = 1;

	if (!cos->s.queue_group) {
		pkt_hdr->dst_queue = cos->s.queue;
		return 0;
	}

	hash = packet_rss_hash(pkt_hdr, cos->s.hash_proto, base);
	/* CLS_COS_QUEUE_MAX is a power of 2 */
	hash = hash & (CLS_COS_QUEUE_MAX - 1);
	tbl_index = (cos->s.index * CLS_COS_QUEUE_MAX) + (hash %
							  cos->s.num_queue);
	pkt_hdr->dst_queue = queue_grp_tbl->s.queue[tbl_index];
	return 0;
}

static uint32_t packet_rss_hash(odp_packet_hdr_t *pkt_hdr,
				odp_cls_hash_proto_t hash_proto,
				const uint8_t *base)
{
	thash_tuple_t tuple;
	const _odp_ipv4hdr_t *ipv4;
	const _odp_udphdr_t *udp;
	const _odp_tcphdr_t *tcp;
	const _odp_ipv6hdr_t *ipv6;
	uint32_t hash;
	uint32_t tuple_len;

	tuple_len = 0;
	hash = 0;
	if (pkt_hdr->p.input_flags.ipv4) {
		if (hash_proto.ipv4) {
			/* add ipv4 */
			ipv4 = (const _odp_ipv4hdr_t *)(base +
				pkt_hdr->p.l3_offset);
			tuple.v4.src_addr = ipv4->src_addr;
			tuple.v4.dst_addr = ipv4->dst_addr;
			tuple_len += 2;
		}

		if (pkt_hdr->p.input_flags.tcp && hash_proto.tcp) {
			/* add tcp */
			tcp = (const _odp_tcphdr_t *)(base +
			       pkt_hdr->p.l4_offset);
			tuple.v4.sport = tcp->src_port;
			tuple.v4.dport = tcp->dst_port;
			tuple_len += 1;
		} else if (pkt_hdr->p.input_flags.udp && hash_proto.udp) {
			/* add udp */
			udp = (const _odp_udphdr_t *)(base +
			       pkt_hdr->p.l4_offset);
			tuple.v4.sport = udp->src_port;
			tuple.v4.dport = udp->dst_port;
			tuple_len += 1;
		}
	} else if (pkt_hdr->p.input_flags.ipv6) {
		if (hash_proto.ipv6) {
			/* add ipv6 */
			ipv6 = (const _odp_ipv6hdr_t *)(base +
				pkt_hdr->p.l3_offset);
			thash_load_ipv6_addr(ipv6, &tuple);
			tuple_len += 8;
		}
		if (pkt_hdr->p.input_flags.tcp && hash_proto.tcp) {
			tcp = (const _odp_tcphdr_t *)(base +
			       pkt_hdr->p.l4_offset);
			tuple.v6.sport = tcp->src_port;
			tuple.v6.dport = tcp->dst_port;
			tuple_len += 1;
		} else if (pkt_hdr->p.input_flags.udp && hash_proto.udp) {
			/* add udp */
			udp = (const _odp_udphdr_t *)(base +
			       pkt_hdr->p.l4_offset);
			tuple.v6.sport = udp->src_port;
			tuple.v6.dport = udp->dst_port;
			tuple_len += 1;
		}
	}
	if (tuple_len)
		hash = thash_softrss((uint32_t *)&tuple,
				     tuple_len, default_rss);
	return hash;
}

static
cos_t *match_qos_l3_cos(pmr_l3_cos_t *l3_cos, const uint8_t *pkt_addr,
			odp_packet_hdr_t *hdr)
{
	uint8_t dscp;
	cos_t *cos = NULL;
	const _odp_ipv4hdr_t *ipv4;
	const _odp_ipv6hdr_t *ipv6;

	if (hdr->p.input_flags.l3 && hdr->p.input_flags.ipv4) {
		ipv4 = (const _odp_ipv4hdr_t *)(pkt_addr + hdr->p.l3_offset);
		dscp = _ODP_IPV4HDR_DSCP(ipv4->tos);
		cos = l3_cos->cos[dscp];
	} else if (hdr->p.input_flags.l3 && hdr->p.input_flags.ipv6) {
		ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + hdr->p.l3_offset);
		dscp = _ODP_IPV6HDR_DSCP(ipv6->ver_tc_flow);
		cos = l3_cos->cos[dscp];
	}

	return cos;
}

static
cos_t *match_qos_l2_cos(pmr_l2_cos_t *l2_cos, const uint8_t *pkt_addr,
			odp_packet_hdr_t *hdr)
{
	cos_t *cos = NULL;
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t qos;

	if (packet_hdr_has_l2(hdr) && hdr->p.input_flags.vlan &&
	    packet_hdr_has_eth(hdr)) {
		eth = (const _odp_ethhdr_t *)(pkt_addr + hdr->p.l2_offset);
		vlan = (const _odp_vlanhdr_t *)(eth + 1);
		qos = odp_be_to_cpu_16(vlan->tci);
		qos = ((qos >> 13) & 0x07);
		cos = l2_cos->cos[qos];
	}
	return cos;
}

/*
 * Select a CoS for the given Packet based on QoS values
 * This function returns the COS object matching the L2 and L3 QoS
 * based on the l3_preference value of the pktio
*/
static
cos_t *match_qos_cos(pktio_entry_t *entry, const uint8_t *pkt_addr,
		     odp_packet_hdr_t *hdr)
{
	classifier_t *cls = &entry->s.cls;
	pmr_l2_cos_t *l2_cos;
	pmr_l3_cos_t *l3_cos;
	cos_t *cos;

	l2_cos = &cls->l2_cos_table;
	l3_cos = &cls->l3_cos_table;

	if (cls->l3_precedence) {
		cos =  match_qos_l3_cos(l3_cos, pkt_addr, hdr);
		if (cos)
			return cos;
		cos = match_qos_l2_cos(l2_cos, pkt_addr, hdr);
		if (cos)
			return cos;
	} else {
		cos = match_qos_l2_cos(l2_cos, pkt_addr, hdr);
		if (cos)
			return cos;
		cos = match_qos_l3_cos(l3_cos, pkt_addr, hdr);
		if (cos)
			return cos;
	}
	return NULL;
}

uint64_t odp_cos_to_u64(odp_cos_t hdl)
{
	return _odp_pri(hdl);
}

uint64_t odp_pmr_to_u64(odp_pmr_t hdl)
{
	return _odp_pri(hdl);
}
