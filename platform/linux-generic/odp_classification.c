/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/classification.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/debug.h>
#include <odp/api/pool.h>
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
#include <inttypes.h>
#include <odp/api/spinlock.h>

/* Debug level for per packet classification operations */
#define CLS_DBG  3
#define MAX_MARK UINT16_MAX

#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a)	odp_spinlock_init(a)

static cos_tbl_t *cos_tbl;
static pmr_tbl_t	*pmr_tbl;
static _cls_queue_grp_tbl_t *queue_grp_tbl;

cls_global_t *_odp_cls_global;

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

	_odp_cls_global = odp_shm_addr(shm);
	memset(_odp_cls_global, 0, sizeof(cls_global_t));

	_odp_cls_global->shm = shm;
	cos_tbl       = &_odp_cls_global->cos_tbl;
	pmr_tbl       = &_odp_cls_global->pmr_tbl;
	queue_grp_tbl = &_odp_cls_global->queue_grp_tbl;

	for (i = 0; i < CLS_COS_MAX_ENTRY; i++) {
		/* init locks */
		cos_t *cos = get_cos_entry_internal(_odp_cos_from_ndx(i));

		LOCK_INIT(&cos->lock);
	}

	for (i = 0; i < CLS_PMR_MAX_ENTRY; i++) {
		/* init locks */
		pmr_t *pmr = get_pmr_entry_internal(_odp_pmr_from_ndx(i));

		LOCK_INIT(&pmr->lock);
	}

	return 0;
}

int _odp_classification_term_global(void)
{
	if (_odp_cls_global && odp_shm_free(_odp_cls_global->shm)) {
		_ODP_ERR("shm free failed\n");
		return -1;
	}

	return 0;
}

void odp_cls_cos_param_init(odp_cls_cos_param_t *param)
{
	memset(param, 0, sizeof(odp_cls_cos_param_t));

	param->queue = ODP_QUEUE_INVALID;
	param->pool = ODP_POOL_INVALID;
#if ODP_DEPRECATED_API
	param->drop_policy = ODP_COS_DROP_NEVER;
#endif
	param->num_queue = 1;
	param->vector.enable = false;
	odp_queue_param_init(&param->queue_param);
}

void odp_cls_pmr_param_init(odp_pmr_param_t *param)
{
	memset(param, 0, sizeof(odp_pmr_param_t));
}

int odp_cls_capability(odp_cls_capability_t *capability)
{
	uint32_t count = 0;

	memset(capability, 0, sizeof(odp_cls_capability_t));

	for (int i = 0; i < CLS_PMR_MAX_ENTRY; i++)
		if (!pmr_tbl->pmr[i].valid)
			count++;

	capability->max_pmr_terms = CLS_PMR_MAX_ENTRY;
	capability->available_pmr_terms = count;
	capability->max_cos = CLS_COS_MAX_ENTRY;
	capability->max_cos_stats = capability->max_cos;
	capability->pmr_range_supported = false;
	capability->supported_terms.all_bits = 0;
	capability->supported_terms.bit.len = 1;
	capability->supported_terms.bit.ethtype_0 = 1;
	capability->supported_terms.bit.ethtype_x = 1;
	capability->supported_terms.bit.vlan_id_0 = 1;
	capability->supported_terms.bit.vlan_id_x = 1;
	capability->supported_terms.bit.vlan_pcp_0 = 1;
	capability->supported_terms.bit.dmac = 1;
	capability->supported_terms.bit.ip_proto = 1;
	capability->supported_terms.bit.ip_dscp = 1;
	capability->supported_terms.bit.udp_dport = 1;
	capability->supported_terms.bit.udp_sport = 1;
	capability->supported_terms.bit.tcp_dport = 1;
	capability->supported_terms.bit.tcp_sport = 1;
	capability->supported_terms.bit.sip_addr = 1;
	capability->supported_terms.bit.dip_addr = 1;
	capability->supported_terms.bit.sip6_addr = 1;
	capability->supported_terms.bit.dip6_addr = 1;
	capability->supported_terms.bit.ipsec_spi = 1;
	capability->supported_terms.bit.custom_frame = 1;
	capability->supported_terms.bit.custom_l3 = 1;
	capability->random_early_detection = ODP_SUPPORT_NO;
	capability->back_pressure = ODP_SUPPORT_NO;
	capability->threshold_red.all_bits = 0;
	capability->threshold_bp.all_bits = 0;
	capability->max_hash_queues = CLS_COS_QUEUE_MAX;
	capability->hash_protocols.proto.ipv4_udp = 1;
	capability->hash_protocols.proto.ipv4_tcp = 1;
	capability->hash_protocols.proto.ipv4 = 1;
	capability->hash_protocols.proto.ipv6_udp = 1;
	capability->hash_protocols.proto.ipv6_tcp = 1;
	capability->hash_protocols.proto.ipv6 = 1;
	capability->max_mark = MAX_MARK;
	capability->stats.cos.counter.discards = 1;
	capability->stats.cos.counter.packets = 1;
	capability->stats.queue.counter.discards = 1;
	capability->stats.queue.counter.packets = 1;

	return 0;
}

void odp_cls_pmr_create_opt_init(odp_pmr_create_opt_t *opt)
{
	opt->terms = NULL;
	opt->num_terms = 0;
	opt->mark = 0;
}

static void _odp_cls_update_hash_proto(cos_t *cos,
				       odp_pktin_hash_proto_t hash_proto)
{
	if (hash_proto.proto.ipv4 || hash_proto.proto.ipv4_tcp ||
	    hash_proto.proto.ipv4_udp)
		cos->hash_proto.ipv4 = 1;
	if (hash_proto.proto.ipv6 || hash_proto.proto.ipv6_tcp ||
	    hash_proto.proto.ipv6_udp)
		cos->hash_proto.ipv6 = 1;
	if (hash_proto.proto.ipv4_tcp || hash_proto.proto.ipv6_tcp)
		cos->hash_proto.tcp = 1;
	if (hash_proto.proto.ipv4_udp || hash_proto.proto.ipv6_udp)
		cos->hash_proto.udp = 1;
}

static inline void _cls_queue_unwind(uint32_t tbl_index, uint32_t j)
{
	while (j > 0)
		odp_queue_destroy(queue_grp_tbl->queue[tbl_index + --j]);
}

odp_cos_t odp_cls_cos_create(const char *name, const odp_cls_cos_param_t *param_in)
{
#if ODP_DEPRECATED_API
	odp_cls_drop_t drop_policy;
#endif
	uint32_t i, j;
	odp_queue_t queue;
	cos_t *cos;
	uint32_t tbl_index;
	odp_cls_cos_param_t param = *param_in;

	if (param.action == ODP_COS_ACTION_DROP) {
		param.num_queue = 1;
		param.queue = ODP_QUEUE_INVALID;
		param.pool = ODP_POOL_INVALID;
		param.vector.enable = false;
	}

	/* num_queue should not be zero */
	if (param.num_queue > CLS_COS_QUEUE_MAX || param.num_queue < 1)
		return ODP_COS_INVALID;

	/* Validate packet vector parameters */
	if (param.vector.enable) {
		odp_pool_t pool = param.vector.pool;
		odp_pool_info_t pool_info;

		if (pool == ODP_POOL_INVALID || odp_pool_info(pool, &pool_info)) {
			_ODP_ERR("invalid packet vector pool\n");
			return ODP_COS_INVALID;
		}
		if (pool_info.params.type != ODP_POOL_VECTOR) {
			_ODP_ERR("wrong pool type\n");
			return ODP_COS_INVALID;
		}
		if (param.vector.max_size == 0) {
			_ODP_ERR("vector.max_size is zero\n");
			return ODP_COS_INVALID;
		}
		if (param.vector.max_size > pool_info.params.vector.max_size) {
			_ODP_ERR("vector.max_size larger than pool max vector size\n");
			return ODP_COS_INVALID;
		}
	}

#if ODP_DEPRECATED_API
	drop_policy = param.drop_policy;
#endif

	for (i = 0; i < CLS_COS_MAX_ENTRY; i++) {
		cos = &cos_tbl->cos_entry[i];
		LOCK(&cos->lock);
		if (0 == cos->valid) {
			char *cos_name = cos->name;

			if (name == NULL) {
				cos_name[0] = 0;
			} else {
				strncpy(cos_name, name, ODP_COS_NAME_LEN - 1);
				cos_name[ODP_COS_NAME_LEN - 1] = 0;
			}
			for (j = 0; j < CLS_PMR_PER_COS_MAX; j++) {
				cos->pmr[j] = NULL;
				cos->linked_cos[j] = NULL;
			}

			cos->num_queue = param.num_queue;

			if (param.num_queue > 1) {
				cos->queue_param = param.queue_param;
				cos->queue_group = true;
				cos->queue = ODP_QUEUE_INVALID;
				_odp_cls_update_hash_proto(cos,
							   param.hash_proto);
				tbl_index = i * CLS_COS_QUEUE_MAX;
				for (j = 0; j < param.num_queue; j++) {
					char name[ODP_QUEUE_NAME_LEN];

					snprintf(name, sizeof(name), "_odp_cos_hq_%u_%u", i, j);
					queue = odp_queue_create(name, &cos->queue_param);
					if (queue == ODP_QUEUE_INVALID) {
						/* unwind the queues */
						_cls_queue_unwind(tbl_index, j);
						UNLOCK(&cos->lock);
						return ODP_COS_INVALID;
					}
					queue_grp_tbl->queue[tbl_index + j] =
							queue;
				}

			} else {
				cos->queue_group = false;
				cos->queue = param.queue;
			}

			odp_atomic_init_u64(&cos->stats.discards, 0);
			odp_atomic_init_u64(&cos->stats.packets, 0);

			/* Initialize statistics counters */
			for (j = 0; j < cos->num_queue; j++) {
				odp_atomic_init_u64(&cos->queue_stats[j].discards, 0);
				odp_atomic_init_u64(&cos->queue_stats[j].packets, 0);
			}

			cos->action = param.action;
			cos->pool = param.pool;
			cos->headroom = 0;
			cos->valid = 1;
#if ODP_DEPRECATED_API
			cos->drop_policy = drop_policy;
#endif
			odp_atomic_init_u32(&cos->num_rule, 0);
			cos->index = i;
			cos->vector = param.vector;
			cos->stats_enable = param.stats_enable;
			UNLOCK(&cos->lock);
			return _odp_cos_from_ndx(i);
		}
		UNLOCK(&cos->lock);
	}

	_ODP_ERR("CLS_COS_MAX_ENTRY reached\n");
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
		LOCK(&pmr_tbl->pmr[i].lock);
		if (0 == pmr_tbl->pmr[i].valid) {
			pmr_tbl->pmr[i].valid = 1;
			pmr_tbl->pmr[i].num_pmr = 0;
			*pmr = &pmr_tbl->pmr[i];
			/* return as locked */
			return _odp_pmr_from_ndx(i);
		}
		UNLOCK(&pmr_tbl->pmr[i].lock);
	}
	_ODP_ERR("CLS_PMR_MAX_ENTRY reached\n");
	return ODP_PMR_INVALID;
}

static
cos_t *get_cos_entry(odp_cos_t cos)
{
	uint32_t cos_id = _odp_cos_to_ndx(cos);

	if (cos_id >= CLS_COS_MAX_ENTRY || cos == ODP_COS_INVALID)
		return NULL;
	if (cos_tbl->cos_entry[cos_id].valid == 0)
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
	if (pmr_tbl->pmr[pmr_id].valid == 0)
		return NULL;
	return &pmr_tbl->pmr[pmr_id];
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (NULL == cos) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	if (cos->queue_group)
		_cls_queue_unwind(cos->index * CLS_COS_QUEUE_MAX, cos->num_queue);

	cos->valid = 0;
	return 0;
}

int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (cos == NULL) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	if (cos->num_queue != 1) {
		_ODP_ERR("Hashing enabled, cannot set queue\n");
		return -1;
	}

	/* Locking is not required as intermittent stale
	data during CoS modification is acceptable*/
	cos->queue = queue_id;
	return 0;
}

odp_queue_t odp_cos_queue(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_QUEUE_INVALID;
	}

	return cos->queue;
}

uint32_t odp_cls_cos_num_queue(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return 0;
	}

	return cos->num_queue;
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
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return 0;
	}

	if (cos->num_queue == 1) {
		if (num == 0)
			return 1;

		queue[0] = cos->queue;
		return 1;
	}

	if (num < cos->num_queue)
		num_queues = num;
	else
		num_queues = cos->num_queue;

	tbl_index = cos->index * CLS_COS_QUEUE_MAX;
	for (i = 0; i < num_queues; i++)
		queue[i] = queue_grp_tbl->queue[tbl_index + i];

	return cos->num_queue;
}

#if ODP_DEPRECATED_API

int odp_cos_drop_set(odp_cos_t cos_id, odp_cls_drop_t drop_policy)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	/*Drop policy is not supported in v1.0*/
	cos->drop_policy = drop_policy;
	return 0;
}

odp_cls_drop_t odp_cos_drop(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);

	if (!cos) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	return cos->drop_policy;
}

#endif

int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		_ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	cos = get_cos_entry(default_cos);
	if (cos == NULL) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	entry->cls.default_cos = cos;
	return 0;
}

int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		_ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}

	cos = get_cos_entry(error_cos);
	if (cos == NULL) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	entry->cls.error_cos = cos;
	return 0;
}

int odp_pktio_skip_set(odp_pktio_t pktio_in, uint32_t offset)
{
	(void)pktio_in;
	(void)offset;

	/* Skipping bytes before parsing is not supported */
	return -ENOTSUP;
}

int odp_pktio_headroom_set(odp_pktio_t pktio_in, uint32_t headroom)
{
	pktio_entry_t *entry = get_pktio_entry(pktio_in);

	if (entry == NULL) {
		_ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	entry->cls.headroom = headroom;
	return 0;
}

int ODP_DEPRECATE(odp_cos_with_l2_priority)(odp_pktio_t pktio_in, uint8_t num_qos,
					    uint8_t qos_table[], odp_cos_t cos_table[])
{
	pmr_l2_cos_t *l2_cos;
	uint32_t i;
	cos_t *cos;
	pktio_entry_t *entry = get_pktio_entry(pktio_in);

	if (entry == NULL) {
		_ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}
	l2_cos = &entry->cls.l2_cos_table;

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

int ODP_DEPRECATE(odp_cos_with_l3_qos)(odp_pktio_t pktio_in, uint32_t num_qos, uint8_t qos_table[],
				       odp_cos_t cos_table[], odp_bool_t l3_preference)
{
	pmr_l3_cos_t *l3_cos;
	uint32_t i;
	pktio_entry_t *entry = get_pktio_entry(pktio_in);
	cos_t *cos;

	if (entry == NULL) {
		_ODP_ERR("Invalid odp_pktio_t handle\n");
		return -1;
	}

	entry->cls.l3_precedence = l3_preference;
	l3_cos = &entry->cls.l3_cos_table;

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

static int pmr_create_term(pmr_term_value_t *value,
			   const odp_pmr_param_t *param)
{
	uint32_t size;
	uint8_t i;
	int custom = 0;
	odp_cls_pmr_term_t term = param->term;

	if (param->range_term) {
		_ODP_ERR("PMR value range not supported\n");
		return -1;
	}

	value->term = term;
	value->range_term = param->range_term;

	switch (term) {
	case ODP_PMR_VLAN_PCP_0:
		/* Fall through */
	case ODP_PMR_IPPROTO:
		/* Fall through */
	case ODP_PMR_IP_DSCP:
		size = 1;
		break;

	case ODP_PMR_ETHTYPE_0:
		/* Fall through */
	case ODP_PMR_ETHTYPE_X:
		/* Fall through */
	case ODP_PMR_VLAN_ID_0:
		/* Fall through */
	case ODP_PMR_VLAN_ID_X:
		/* Fall through */
	case ODP_PMR_UDP_DPORT:
		/* Fall through */
	case ODP_PMR_TCP_DPORT:
		/* Fall through */
	case ODP_PMR_UDP_SPORT:
		/* Fall through */
	case ODP_PMR_TCP_SPORT:
		size = 2;
		break;

	case ODP_PMR_LEN:
		/* Fall through */
	case ODP_PMR_SIP_ADDR:
		/* Fall through */
	case ODP_PMR_DIP_ADDR:
		/* Fall through */
	case ODP_PMR_IPSEC_SPI:
		/* Fall through */
	case ODP_PMR_LD_VNI:
		size = 4;
		break;

	case ODP_PMR_DMAC:
		size = 6;
		break;

	case ODP_PMR_SIP6_ADDR:
		/* Fall through */
	case ODP_PMR_DIP6_ADDR:
		size = 16;
		break;

	case ODP_PMR_CUSTOM_FRAME:
		/* Fall through */
	case ODP_PMR_CUSTOM_L3:
		custom = 1;
		size = MAX_PMR_TERM_SIZE;
		break;

	default:
		_ODP_ERR("Bad PMR term\n");
		return -1;
	}

	if ((!custom && param->val_sz != size) ||
	    (custom && param->val_sz > size)) {
		_ODP_ERR("Bad PMR value size: %u\n", param->val_sz);
		return -1;
	}

	memset(&value->match, 0, sizeof(value->match));
	memcpy(&value->match.value, param->match.value, param->val_sz);
	memcpy(&value->match.mask, param->match.mask, param->val_sz);

	for (i = 0; i < param->val_sz; i++)
		value->match.value_u8[i] &= value->match.mask_u8[i];

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
	if (pmr == NULL || pmr->src_cos == NULL)
		return -1;

	src_cos = pmr->src_cos;
	LOCK(&src_cos->lock);
	loc = odp_atomic_load_u32(&src_cos->num_rule);
	if (loc == 0)
		goto no_rule;
	loc -= 1;
	for (i = 0; i <= loc; i++)
		if (src_cos->pmr[i] == pmr) {
			src_cos->pmr[i] = src_cos->pmr[loc];
			src_cos->linked_cos[i] = src_cos->linked_cos[loc];
		}
	odp_atomic_dec_u32(&src_cos->num_rule);

no_rule:
	pmr->valid = 0;
	UNLOCK(&src_cos->lock);
	return 0;
}

static odp_pmr_t cls_pmr_create(const odp_pmr_param_t *terms, int num_terms, uint16_t mark,
				odp_cos_t src_cos, odp_cos_t dst_cos)
{
	pmr_t *pmr;
	int i;
	odp_pmr_t id;
	uint32_t loc;
	cos_t *cos_src = get_cos_entry(src_cos);
	cos_t *cos_dst = get_cos_entry(dst_cos);

	if (NULL == cos_src || NULL == cos_dst) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_PMR_INVALID;
	}

	if (num_terms > CLS_PMRTERM_MAX) {
		_ODP_ERR("no of terms greater than supported CLS_PMRTERM_MAX\n");
		return ODP_PMR_INVALID;
	}

	if (CLS_PMR_PER_COS_MAX == odp_atomic_load_u32(&cos_src->num_rule))
		return ODP_PMR_INVALID;

	id = alloc_pmr(&pmr);
	/*if alloc_pmr is successful it returns with the acquired lock*/
	if (id == ODP_PMR_INVALID)
		return id;

	pmr->num_pmr = num_terms;
	for (i = 0; i < num_terms; i++) {
		if (pmr_create_term(&pmr->pmr_term_value[i], &terms[i])) {
			pmr->valid = 0;
			UNLOCK(&pmr->lock);
			return ODP_PMR_INVALID;
		}
	}

	pmr->mark = mark;

	loc = odp_atomic_fetch_inc_u32(&cos_src->num_rule);
	cos_src->pmr[loc] = pmr;
	cos_src->linked_cos[loc] = cos_dst;
	pmr->src_cos = cos_src;

	UNLOCK(&pmr->lock);
	return id;
}

odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
			     odp_cos_t src_cos, odp_cos_t dst_cos)
{
	return cls_pmr_create(terms, num_terms, 0, src_cos, dst_cos);
}

odp_pmr_t odp_cls_pmr_create_opt(const odp_pmr_create_opt_t *opt,
				 odp_cos_t src_cos, odp_cos_t dst_cos)
{
	if (opt == NULL) {
		_ODP_ERR("Bad parameter\n");
		return ODP_PMR_INVALID;
	}

	if (opt->mark > MAX_MARK) {
		_ODP_ERR("Too large mark value: %" PRIu64 "\n", opt->mark);
		return ODP_PMR_INVALID;
	}

	return cls_pmr_create(opt->terms, opt->num_terms, opt->mark, src_cos, dst_cos);
}

int odp_cls_cos_pool_set(odp_cos_t cos_id, odp_pool_t pool)
{
	cos_t *cos;

	cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	cos->pool = pool;

	return 0;
}

odp_pool_t odp_cls_cos_pool(odp_cos_t cos_id)
{
	cos_t *cos;

	cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return ODP_POOL_INVALID;
	}

	return cos->pool;
}

static inline int verify_pmr_packet_len(odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	if (term_value->match.value == (packet_len(pkt_hdr) &
				     term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_proto(const _odp_ipv4hdr_t *ipv4, pmr_term_value_t *term_value)
{
	uint8_t proto;

	proto = ipv4->proto;
	if (term_value->match.value == (proto & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv6_next_hdr(const _odp_ipv6hdr_t *ipv6, pmr_term_value_t *term_value)
{
	uint8_t next_hdr;

	next_hdr = ipv6->next_hdr;
	if (term_value->match.value == (next_hdr & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_dscp(const _odp_ipv4hdr_t *ipv4, pmr_term_value_t *term_value)
{
	uint8_t dscp;

	dscp = _ODP_IPV4HDR_DSCP(ipv4->tos);
	if (term_value->match.value == (dscp & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv6_dscp(const _odp_ipv6hdr_t *ipv6, pmr_term_value_t *term_value)
{
	uint8_t dscp;

	dscp = _ODP_IPV6HDR_DSCP(odp_be_to_cpu_32(ipv6->ver_tc_flow));
	if (term_value->match.value == (dscp & term_value->match.mask))
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
	ipaddr = ip->src_addr;
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
	ipaddr = ip->dst_addr;
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
	sport = tcp->src_port;
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
	dport = tcp->dst_port;
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
	dport = udp->dst_port;
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
	sport = udp->src_port;
	if (term_value->match.value == (sport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_dmac(const uint8_t *pkt_addr,
				  odp_packet_hdr_t *pkt_hdr,
				  pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	uint16_t dmac[3];
	uint16_t *mask  = (uint16_t *)&term_value->match.mask;
	uint16_t *value = (uint16_t *)&term_value->match.value;

	if (!packet_hdr_has_eth(pkt_hdr))
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	memcpy(dmac, eth->dst.addr, _ODP_ETHADDR_LEN);
	dmac[0] &= mask[0];
	dmac[1] &= mask[1];
	dmac[2] &= mask[2];

	if (value[0] == dmac[0] && value[1] == dmac[1] && value[2] == dmac[2])
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
	memcpy(addr, ipv6->src_addr.u64, _ODP_IPV6ADDR_LEN);

	addr[0] = addr[0] & term_value->match.mask_u64[0];
	addr[1] = addr[1] & term_value->match.mask_u64[1];

	if (addr[0] == term_value->match.value_u64[0] &&
	    addr[1] == term_value->match.value_u64[1])
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
	memcpy(addr, ipv6->dst_addr.u64, _ODP_IPV6ADDR_LEN);

	addr[0] = addr[0] & term_value->match.mask_u64[0];
	addr[1] = addr[1] & term_value->match.mask_u64[1];

	if (addr[0] == term_value->match.value_u64[0] &&
	    addr[1] == term_value->match.value_u64[1])
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
	tci = vlan->tci;
	vlan_id = tci & odp_cpu_to_be_16(0x0fff);

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

	tci = vlan->tci;
	vlan_id = tci & odp_cpu_to_be_16(0x0fff);

	if (term_value->match.value == (vlan_id & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_vlan_pcp_0(const uint8_t *pkt_addr, odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t tci;
	uint8_t pcp;

	if (!packet_hdr_has_eth(pkt_hdr) || !pkt_hdr->p.input_flags.vlan)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);
	tci = odp_be_to_cpu_16(vlan->tci);
	pcp = tci >> _ODP_VLANHDR_PCP_SHIFT;

	if (term_value->match.value == (pcp & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipsec_spi(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint32_t spi;

	pkt_addr += pkt_hdr->p.l4_offset;

	if (pkt_hdr->p.input_flags.ipsec_ah)
		spi = ((const _odp_ahhdr_t *)pkt_addr)->spi;
	else if (pkt_hdr->p.input_flags.ipsec_esp)
		spi = ((const _odp_esphdr_t *)pkt_addr)->spi;
	else
		return 0;

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
	uint32_t i;
	uint8_t val;
	uint32_t offset = term_value->offset;
	uint32_t val_sz = term_value->val_sz;

	_ODP_ASSERT(val_sz <= MAX_PMR_TERM_SIZE);

	if (packet_len(pkt_hdr) <= offset + val_sz)
		return 0;

	pkt_addr += offset;

	for (i = 0; i < val_sz; i++) {
		val = pkt_addr[i] & term_value->match.mask_u8[i];

		if (val != term_value->match.value_u8[i])
			return 0;
	}

	return 1;
}

static inline int verify_pmr_custom_l3(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint32_t i;
	uint8_t val;
	uint32_t l3_offset = pkt_hdr->p.l3_offset;
	uint32_t offset = l3_offset + term_value->offset;
	uint32_t val_sz = term_value->val_sz;

	_ODP_ASSERT(val_sz <= MAX_PMR_TERM_SIZE);

	if (pkt_hdr->p.input_flags.l2 == 0 ||
	    l3_offset == ODP_PACKET_OFFSET_INVALID)
		return 0;

	if (packet_len(pkt_hdr) <= offset + val_sz)
		return 0;

	pkt_addr += offset;

	for (i = 0; i < val_sz; i++) {
		val = pkt_addr[i] & term_value->match.mask_u8[i];

		if (val != term_value->match.value_u8[i])
			return 0;
	}

	return 1;
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
	ethtype = eth->type;

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

	ethtype = vlan->type;

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
	const _odp_ipv4hdr_t *ipv4 = NULL;
	const _odp_ipv6hdr_t *ipv6 = NULL;

	/* Locking is not required as PMR rules for in-flight packets
	delivery during a PMR change is indeterminate*/

	if (!pmr->valid)
		return 0;
	num_pmr = pmr->num_pmr;

	if (pkt_hdr->p.input_flags.ipv4)
		ipv4 = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	if (pkt_hdr->p.input_flags.ipv6)
		ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);

	/* Iterate through list of PMR Term values in a pmr_t */
	for (i = 0; i < num_pmr; i++) {
		term_value = &pmr->pmr_term_value[i];
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
		case ODP_PMR_VLAN_PCP_0:
			if (!verify_pmr_vlan_pcp_0(pkt_addr, pkt_hdr, term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_DMAC:
			if (!verify_pmr_dmac(pkt_addr, pkt_hdr,
					     term_value))
				pmr_failure = 1;
			break;
		case ODP_PMR_IPPROTO:
			if (ipv4) {
				if (!verify_pmr_ipv4_proto(ipv4, term_value))
					pmr_failure = 1;
			} else if (ipv6) {
				if (!verify_pmr_ipv6_next_hdr(ipv6, term_value))
					pmr_failure = 1;
			} else {
				pmr_failure = 1;
			}
			break;
		case ODP_PMR_IP_DSCP:
			if (ipv4) {
				if (!verify_pmr_ipv4_dscp(ipv4, term_value))
					pmr_failure = 1;
			} else if (ipv6) {
				if (!verify_pmr_ipv6_dscp(ipv6, term_value))
					pmr_failure = 1;
			} else {
				pmr_failure = 1;
			}
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
		case ODP_PMR_CUSTOM_L3:
			if (!verify_pmr_custom_l3(pkt_addr, pkt_hdr,
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
			return 0;
	}
	return 1;
}

static const char *format_pmr_name(odp_cls_pmr_term_t pmr_term)
{
	const char *name;

	switch (pmr_term) {
	case ODP_PMR_LEN:
		name = "PMR_LEN";
		break;
	case ODP_PMR_ETHTYPE_0:
		name = "PMR_ETHTYPE_0";
		break;
	case ODP_PMR_ETHTYPE_X:
		name = "PMR_ETHTYPE_X";
		break;
	case ODP_PMR_VLAN_ID_0:
		name = "PMR_VLAN_ID_0";
		break;
	case ODP_PMR_VLAN_ID_X:
		name = "PMR_VLAN_ID_X";
		break;
	case ODP_PMR_VLAN_PCP_0:
		name = "PMR_VLAN_PCP_0";
		break;
	case ODP_PMR_DMAC:
		name = "PMR_DMAC";
		break;
	case ODP_PMR_IPPROTO:
		name = "PMR_IPPROTO";
		break;
	case ODP_PMR_IP_DSCP:
		name = "PMR_IP_DSCP";
		break;
	case ODP_PMR_UDP_DPORT:
		name = "PMR_UDP_DPORT";
		break;
	case ODP_PMR_TCP_DPORT:
		name = "PMR_TCP_DPORT";
		break;
	case ODP_PMR_UDP_SPORT:
		name = "PMR_UDP_SPORT";
		break;
	case ODP_PMR_TCP_SPORT:
		name = "PMR_TCP_SPORT";
		break;
	case ODP_PMR_SIP_ADDR:
		name = "PMR_SIP_ADDR";
		break;
	case ODP_PMR_DIP_ADDR:
		name = "PMR_DIP_ADDR";
		break;
	case ODP_PMR_SIP6_ADDR:
		name = "PMR_SIP6_ADDR";
		break;
	case ODP_PMR_DIP6_ADDR:
		name = "PMR_DIP6_ADDR";
		break;
	case ODP_PMR_IPSEC_SPI:
		name = "PMR_IPSEC_SPI";
		break;
	case ODP_PMR_LD_VNI:
		name = "PMR_LD_VNI";
		break;
	case ODP_PMR_CUSTOM_FRAME:
		name = "PMR_CUSTOM_FRAME";
		break;
	case ODP_PMR_CUSTOM_L3:
		name = "PMR_CUSTOM_L3";
		break;
	default:
		name = "unknown";
		break;
	}

	return name;
}

static inline void pmr_debug_print(pmr_t *pmr, cos_t *cos)
{
	uint32_t i;
	const char *pmr_name;
	const char *cos_name = cos->name;
	uint32_t cos_index = cos->index;
	uint32_t num_pmr = pmr->num_pmr;

	if (ODP_DEBUG_PRINT == 0)
		return;

	if (num_pmr == 1) {
		pmr_name = format_pmr_name(pmr->pmr_term_value[0].term);
		ODP_DBG_RAW(CLS_DBG, "  PMR matched: %s -> cos: %s(%u)\n", pmr_name, cos_name,
			    cos_index);
		return;
	}

	ODP_DBG_RAW(CLS_DBG, "  PMRs matched:");
	for (i = 0; i < num_pmr; i++) {
		pmr_name = format_pmr_name(pmr->pmr_term_value[i].term);
		ODP_DBG_RAW(CLS_DBG, " %s", pmr_name);
	}

	ODP_DBG_RAW(CLS_DBG, " -> cos: %s(%u)\n", cos_name, cos_index);
}

/*
 * Match a PMR chain with a Packet and return matching CoS
 * This function performs a depth-first search in the CoS tree.
 */
static cos_t *match_pmr_cos(cos_t *cos, const uint8_t *pkt_addr, odp_packet_hdr_t *hdr)
{
	pmr_t *pmr_match = NULL;

	while (1) {
		uint32_t i, num_rule = odp_atomic_load_u32(&cos->num_rule);

		for (i = 0; i < num_rule; i++) {
			pmr_t *pmr = cos->pmr[i];
			struct cos_s *linked_cos = cos->linked_cos[i];

			if (odp_unlikely(!linked_cos->valid))
				continue;

			if (verify_pmr(pmr, pkt_addr, hdr)) {
				/* PMR matched */

				pmr_match = pmr;
				cos = linked_cos;

				pmr_debug_print(pmr, cos);

				if (cos->stats_enable)
					odp_atomic_inc_u64(&cos->stats.packets);

				break;
			}
		}

		/* If no PMR matched, the current CoS is the best match. */
		if (i == num_rule)
			break;
	}

	if (pmr_match) {
		hdr->p.input_flags.cls_mark = 0;
		if (pmr_match->mark) {
			hdr->p.input_flags.cls_mark = 1;
			hdr->cls_mark = pmr_match->mark;
		}
	}

	return cos;
}

int _odp_pktio_classifier_init(pktio_entry_t *entry)
{
	classifier_t *cls;

	/* classifier lock should be acquired by the calling function */
	if (entry == NULL)
		return -1;
	cls = &entry->cls;
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
	cos_t *cos;
	cos_t *default_cos;
	classifier_t *cls;

	cls = &entry->cls;
	default_cos = cls->default_cos;

	/* Return error cos for error packet */
	if (pkt_hdr->p.flags.all.error) {
		cos = cls->error_cos;
		goto done;
	}

	/* Calls all the PMRs attached at the PKTIO level*/
	if (default_cos && default_cos->valid) {
		cos = match_pmr_cos(default_cos, pkt_addr, pkt_hdr);
		if (cos && cos != default_cos)
			return cos;
	}

	cos = match_qos_cos(entry, pkt_addr, pkt_hdr);
	if (cos) {
		ODP_DBG_RAW(CLS_DBG, "  QoS matched -> cos: %s(%u)\n", cos->name, cos->index);
		goto done;
	}

	ODP_DBG_RAW(CLS_DBG, "  No match -> default cos\n");
	cos = cls->default_cos;

done:
	if (cos && cos->stats_enable)
		odp_atomic_inc_u64(&cos->stats.packets);

	return cos;
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
 * @retval 0 success
 * @retval -1 drop packet and increment in_discards
 * @retval 1 drop packet
 *
 * @note *base is not released
 */
int _odp_cls_classify_packet(pktio_entry_t *entry, const uint8_t *base,
			     odp_pool_t *pool, odp_packet_hdr_t *pkt_hdr)
{
	cos_t *cos;
	uint32_t tbl_index;
	uint32_t hash;

	ODP_DBG_LVL(CLS_DBG, "Classify packet from %s\n", entry->full_name);

	cos = cls_select_cos(entry, base, pkt_hdr);

	if (cos == NULL)
		return -1;

	if (cos->action == ODP_COS_ACTION_DROP)
		return 1;

	if (cos->queue == ODP_QUEUE_INVALID && cos->num_queue == 1) {
		odp_atomic_inc_u64(&cos->stats.discards);
		return 1;
	}

	*pool = cos->pool;
	if (*pool == ODP_POOL_INVALID)
		*pool = entry->pool;

	pkt_hdr->p.input_flags.dst_queue = 1;
	pkt_hdr->cos = cos->index;

	if (!cos->queue_group) {
		pkt_hdr->dst_queue = cos->queue;
		return 0;
	}

	hash = packet_rss_hash(pkt_hdr, cos->hash_proto, base);
	/* CLS_COS_QUEUE_MAX is a power of 2 */
	hash = hash & (CLS_COS_QUEUE_MAX - 1);
	tbl_index = (cos->index * CLS_COS_QUEUE_MAX) + (hash %
							  cos->num_queue);
	pkt_hdr->dst_queue = queue_grp_tbl->queue[tbl_index];
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
	classifier_t *cls = &entry->cls;
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

int odp_cls_cos_stats(odp_cos_t hdl, odp_cls_cos_stats_t *stats)
{
	cos_t *cos = get_cos_entry(hdl);

	if (odp_unlikely(cos == NULL)) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	if (odp_unlikely(stats == NULL)) {
		_ODP_ERR("Output structure NULL\n");
		return -1;
	}

	memset(stats, 0, sizeof(*stats));
	stats->discards = odp_atomic_load_u64(&cos->stats.discards);
	stats->packets = odp_atomic_load_u64(&cos->stats.packets);

	return 0;
}

int odp_cls_queue_stats(odp_cos_t hdl, odp_queue_t queue,
			odp_cls_queue_stats_t *stats)
{
	cos_t *cos = get_cos_entry(hdl);
	int queue_idx;

	if (odp_unlikely(cos == NULL)) {
		_ODP_ERR("Invalid odp_cos_t handle\n");
		return -1;
	}

	if (odp_unlikely(stats == NULL)) {
		_ODP_ERR("Output structure NULL\n");
		return -1;
	}

	queue_idx = _odp_cos_queue_idx(cos, queue);
	if (odp_unlikely(queue_idx < 0)) {
		_ODP_ERR("Invalid odp_queue_t handle\n");
		return -1;
	}

	memset(stats, 0, sizeof(odp_cls_queue_stats_t));
	stats->discards = odp_atomic_load_u64(&cos->queue_stats[queue_idx].discards);
	stats->packets = odp_atomic_load_u64(&cos->queue_stats[queue_idx].packets);

	return 0;
}

static
void print_cos_ident(cos_t *cos)
{
	if (strlen(cos->name))
		_ODP_PRINT("%s", cos->name);

	_ODP_PRINT("(%" PRIu64 ")\n", odp_cos_to_u64(_odp_cos_from_ndx(cos->index)));
}

static
void print_queue_ident(odp_queue_t q)
{
	odp_queue_info_t info;

	if (!odp_queue_info(q, &info) && strlen(info.name))
		_ODP_PRINT("        %s\n", info.name);
	else
		_ODP_PRINT("        %" PRIx64 "\n", odp_queue_to_u64(q));
}

static
void print_hex(const void *vp, int len)
{
	const uint8_t *p = vp;

	for (int i = 0; i < len; i++)
		_ODP_PRINT("%02x", *p++);
}

static
void cls_print_cos(cos_t *cos)
{
	uint32_t tbl_index = cos->index * CLS_COS_QUEUE_MAX;
	uint32_t num_rule = odp_atomic_load_u32(&cos->num_rule);
	bool first = true;

	_ODP_PRINT("cos: ");
	print_cos_ident(cos);
	_ODP_PRINT("    queues:\n");

	if (!cos->queue_group) {
		print_queue_ident(cos->queue);
	} else {
		for (uint32_t i = 0; i < cos->num_queue; i++)
			print_queue_ident(queue_grp_tbl->queue[tbl_index + i]);
	}

	for (uint32_t j = 0; j < num_rule; j++) {
		pmr_t *pmr = cos->pmr[j];

		LOCK(&pmr->lock);
		for (uint32_t k = 0; k < pmr->num_pmr; k++) {
			pmr_term_value_t *v = &pmr->pmr_term_value[k];

			if (first)
				_ODP_PRINT("    rules: ");
			else
				_ODP_PRINT("           ");

			first = false;

			_ODP_PRINT("%s: ", format_pmr_name(v->term));

			if (v->term == ODP_PMR_CUSTOM_FRAME ||
			    v->term == ODP_PMR_CUSTOM_L3)
				_ODP_PRINT("offset:%" PRIu32 " ", v->offset);

			if (v->range_term) {
				_ODP_PRINT("<range>");
			} else {
				print_hex(v->match.value_u8, v->val_sz);
				_ODP_PRINT(" ");
				print_hex(v->match.mask_u8, v->val_sz);
			}

			_ODP_PRINT(" -> ");

			if (pmr->mark)
				_ODP_PRINT("mark:%" PRIu16 " ", pmr->mark);

			print_cos_ident(cos->linked_cos[j]);
		}
		UNLOCK(&pmr->lock);
	}
}

void odp_cls_print_all(void)
{
	_ODP_PRINT("\n"
		  "Classifier info\n"
		  "---------------\n\n");

	for (uint32_t i = 0; i < CLS_COS_MAX_ENTRY; i++) {
		cos_t *cos = &cos_tbl->cos_entry[i];

		LOCK(&cos->lock);
		if (cos->valid)
			cls_print_cos(cos);
		UNLOCK(&cos->lock);
	}
}
