/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/proto_stats.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_io_inlines.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/time_inlines.h>

#include <odp/autoheader_internal.h>
#include <odp_classification_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_vector_internal.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_pcapng.h>
#include <odp_queue_if.h>
#include <odp_schedule_if.h>

#include <ifaddrs.h>
#include <inttypes.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

/* Sleep this many microseconds between pktin receive calls. Must be smaller
 * than 1000000 (a million), i.e. smaller than a second. */
#define SLEEP_USEC  1

/* Check total sleep time about every SLEEP_CHECK * SLEEP_USEC microseconds.
 * Must be power of two. */
#define SLEEP_CHECK 32

/* Max wait time supported to avoid potential overflow */
#define MAX_WAIT_TIME (UINT64_MAX / 1024)

/* One hour maximum aging timeout, no real limitations imposed by the implementation other than
 * integer width, so just use some value. */
#define MAX_TX_AGING_TMO_NS 3600000000000ULL

typedef struct {
	union {
		struct {
			odp_buffer_t buf;
			const void *user_ptr;
			odp_queue_t queue;
		};

		odp_atomic_u32_t *status;
	};
	uint16_t idx;
	uint8_t mode;
} tx_compl_info_t;

/* Global variables */
static pktio_global_t *pktio_global;

/* pktio pointer entries ( for inlines) */
void *_odp_pktio_entry_ptr[CONFIG_PKTIO_ENTRIES];

static inline pktio_entry_t *pktio_entry_by_index(int index)
{
	return _odp_pktio_entry_ptr[index];
}

static int read_config_file(pktio_global_t *pktio_glb)
{
	const char *str;
	int val = 0;

	_ODP_PRINT("Packet IO config:\n");

	str = "pktio.pktin_frame_offset";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val < 0 || val > UINT16_MAX) {
		_ODP_ERR("Bad value %s = %i\n", str, val);
		return -1;
	}

	pktio_glb->config.pktin_frame_offset = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	str = "pktio.tx_compl_pool_size";
	if (!_odp_libconfig_lookup_int(str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}

	if (val < 0) {
		_ODP_ERR("Bad value %s = %i\n", str, val);
		return -1;
	}

	pktio_glb->config.tx_compl_pool_size = val;
	_ODP_PRINT("  %s: %i\n", str, val);

	_ODP_PRINT("\n");

	return 0;
}

int _odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int i;
	odp_shm_t shm;
	int pktio_if;

	shm = odp_shm_reserve("_odp_pktio_global", sizeof(pktio_global_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	pktio_global = odp_shm_addr(shm);
	memset(pktio_global, 0, sizeof(pktio_global_t));
	pktio_global->shm = shm;

	odp_spinlock_init(&pktio_global->lock);

	if (read_config_file(pktio_global)) {
		odp_shm_free(shm);
		pktio_global = NULL;
		return -1;
	}

	for (i = 0; i < CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry = &pktio_global->entries[i];

		pktio_entry->handle = _odp_cast_scalar(odp_pktio_t, i + 1);
		odp_ticketlock_init(&pktio_entry->rxl);
		odp_ticketlock_init(&pktio_entry->txl);

		_odp_pktio_entry_ptr[i] = pktio_entry;
	}

	for (pktio_if = 0; _odp_pktio_if_ops[pktio_if]; ++pktio_if) {
		if (_odp_pktio_if_ops[pktio_if]->init_global)
			if (_odp_pktio_if_ops[pktio_if]->init_global()) {
				_ODP_ERR("failed to initialized pktio type %d", pktio_if);
				return -1;
			}
	}

	if (_ODP_PCAPNG) {
		if (_odp_pcapng_init_global()) {
			_ODP_ERR("Failed to initialize pcapng\n");
			return -1;
		}
	}

	return 0;
}

int _odp_pktio_init_local(void)
{
	int pktio_if;

	for (pktio_if = 0; _odp_pktio_if_ops[pktio_if]; ++pktio_if) {
		if (_odp_pktio_if_ops[pktio_if]->init_local)
			if (_odp_pktio_if_ops[pktio_if]->init_local()) {
				_ODP_ERR("failed to initialized pktio type %d", pktio_if);
				return -1;
			}
	}

	return 0;
}

static inline int is_free(pktio_entry_t *entry)
{
	return (entry->state == PKTIO_STATE_FREE);
}

static void lock_entry(pktio_entry_t *entry)
{
	odp_ticketlock_lock(&entry->rxl);
	odp_ticketlock_lock(&entry->txl);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_ticketlock_unlock(&entry->txl);
	odp_ticketlock_unlock(&entry->rxl);
}

/**
 * Strip optional pktio type from device name by moving start pointer
 *
 * @param      name      Packet IO device name
 * @param[out] type_out  Optional char array (len = PKTIO_NAME_LEN) for storing
 *                       pktio type. Ignored when NULL.
 *
 * @return Pointer to the beginning of device name
 */
static const char *strip_pktio_type(const char *name, char *type_out)
{
	const char *if_name;

	if (type_out)
		type_out[0] = '\0';

	/* Strip pktio type prefix <pktio_type>:<if_name> */
	if_name = strchr(name, ':');

	if (if_name) {
		int pktio_if;
		int type_len = if_name - name;
		char pktio_type[type_len + 1];

		strncpy(pktio_type, name, type_len);
		pktio_type[type_len] = '\0';

		/* Remove colon */
		if_name++;

		/* Match if_type to enabled pktio devices */
		for (pktio_if = 0; _odp_pktio_if_ops[pktio_if]; pktio_if++) {
			if (!strcmp(pktio_type, _odp_pktio_if_ops[pktio_if]->name)) {
				if (type_out)
					strcpy(type_out, pktio_type);
				/* Some pktio devices expect device names to
				 * begin with pktio type */
				if (!strcmp(pktio_type, "ipc") ||
				    !strcmp(pktio_type, "null") ||
				    !strcmp(pktio_type, "pcap") ||
				    !strcmp(pktio_type, "tap"))
					return name;

				return if_name;
			}
		}
	}
	return name;
}

static void init_out_queues(pktio_entry_t *entry)
{
	int i;

	for (i = 0; i < ODP_PKTOUT_MAX_QUEUES; i++) {
		entry->out_queue[i].queue  = ODP_QUEUE_INVALID;
		entry->out_queue[i].pktout = PKTOUT_INVALID;
	}
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	int i;

	/* Clear all flags */
	entry->enabled.all_flags = 0;

	entry->tx_compl_pool = ODP_POOL_INVALID;
	entry->tx_compl_status_shm = ODP_SHM_INVALID;

	odp_atomic_init_u64(&entry->stats_extra.in_discards, 0);
	odp_atomic_init_u64(&entry->stats_extra.in_errors, 0);
	odp_atomic_init_u64(&entry->stats_extra.out_discards, 0);
	odp_atomic_init_u64(&entry->tx_ts, 0);

	for (i = 0; i < ODP_PKTIN_MAX_QUEUES; i++) {
		entry->in_queue[i].queue = ODP_QUEUE_INVALID;
		entry->in_queue[i].pktin = PKTIN_INVALID;
	}

	init_out_queues(entry);

	_odp_pktio_classifier_init(entry);
}

static odp_pktio_t setup_pktio_entry(const char *name, odp_pool_t pool,
				     const odp_pktio_param_t *param)
{
	odp_pktio_t hdl;
	pktio_entry_t *pktio_entry;
	int i, pktio_if;
	char pktio_type[PKTIO_NAME_LEN];
	const char *if_name;
	uint16_t pktin_frame_offset = pktio_global->config.pktin_frame_offset;
	int ret = -1;

	if (strlen(name) >= PKTIO_NAME_LEN - 1) {
		/* ioctl names limitation */
		_ODP_ERR("pktio name %s is too long (max: %d chars)\n", name, PKTIO_NAME_LEN - 1);
		return ODP_PKTIO_INVALID;
	}

	if_name = strip_pktio_type(name, pktio_type);

	for (i = 0; i < CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry = &pktio_global->entries[i];
		if (is_free(pktio_entry)) {
			lock_entry(pktio_entry);
			if (is_free(pktio_entry))
				break;

			unlock_entry(pktio_entry);
		}
	}

	if (i == CONFIG_PKTIO_ENTRIES) {
		_ODP_ERR("All pktios used already\n");
		return ODP_PKTIO_INVALID;
	}

	/* Entry was found and is now locked */
	pktio_entry->state = PKTIO_STATE_ACTIVE;
	hdl = pktio_entry->handle;

	init_pktio_entry(pktio_entry);

	snprintf(pktio_entry->name, sizeof(pktio_entry->name), "%s", if_name);
	snprintf(pktio_entry->full_name, sizeof(pktio_entry->full_name), "%s", name);
	pktio_entry->pool = pool;
	memcpy(&pktio_entry->param, param, sizeof(odp_pktio_param_t));
	pktio_entry->pktin_frame_offset = pktin_frame_offset;

	odp_pktio_config_init(&pktio_entry->config);

	for (pktio_if = 0; _odp_pktio_if_ops[pktio_if]; ++pktio_if) {
		/* Only use explicitly defined pktio type */
		if (strlen(pktio_type) &&
		    strcmp(_odp_pktio_if_ops[pktio_if]->name, pktio_type))
			continue;

		ret = _odp_pktio_if_ops[pktio_if]->open(hdl, pktio_entry, if_name, pool);

		if (!ret)
			break;
	}

	if (ret != 0) {
		pktio_entry->state = PKTIO_STATE_FREE;
		unlock_entry(pktio_entry);
		_ODP_ERR("Unable to init any I/O type.\n");
		return ODP_PKTIO_INVALID;
	}

	pktio_entry->state = PKTIO_STATE_OPENED;
	pktio_entry->ops = _odp_pktio_if_ops[pktio_if];
	unlock_entry(pktio_entry);

	return hdl;
}

static int pool_type_is_packet(odp_pool_t pool)
{
	odp_pool_info_t pool_info;

	if (pool == ODP_POOL_INVALID)
		return 0;

	if (odp_pool_info(pool, &pool_info) != 0)
		return 0;

	return pool_info.params.type == ODP_POOL_PACKET;
}

static const char *driver_name(odp_pktio_t hdl)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return "bad handle";
	}

	return entry->ops->name;
}

odp_pktio_t odp_pktio_open(const char *name, odp_pool_t pool,
			   const odp_pktio_param_t *param)
{
	odp_pktio_t hdl;
	odp_pktio_param_t default_param;

	if (param == NULL) {
		odp_pktio_param_init(&default_param);
		param = &default_param;
	}

	_ODP_ASSERT(pool_type_is_packet(pool));

	hdl = odp_pktio_lookup(name);
	if (hdl != ODP_PKTIO_INVALID) {
		_ODP_ERR("pktio device %s already opened\n", name);
		return ODP_PKTIO_INVALID;
	}

	odp_spinlock_lock(&pktio_global->lock);
	hdl = setup_pktio_entry(name, pool, param);
	odp_spinlock_unlock(&pktio_global->lock);

	_ODP_DBG("interface: %s, driver: %s\n", name, driver_name(hdl));

	return hdl;
}

static int _pktio_close(pktio_entry_t *entry)
{
	int ret;
	int state = entry->state;

	if (state != PKTIO_STATE_OPENED &&
	    state != PKTIO_STATE_STOPPED &&
	    state != PKTIO_STATE_STOP_PENDING)
		return -1;

	ret = entry->ops->close(entry);
	if (ret)
		return -1;

	if (state == PKTIO_STATE_STOP_PENDING)
		entry->state = PKTIO_STATE_CLOSE_PENDING;
	else
		entry->state = PKTIO_STATE_FREE;

	return 0;
}

static void destroy_in_queues(pktio_entry_t *entry, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		if (entry->in_queue[i].queue != ODP_QUEUE_INVALID) {
			odp_queue_destroy(entry->in_queue[i].queue);
			entry->in_queue[i].queue = ODP_QUEUE_INVALID;
		}
	}
}

static void destroy_out_queues(pktio_entry_t *entry, int num)
{
	int i, rc;

	for (i = 0; i < num; i++) {
		if (entry->out_queue[i].queue != ODP_QUEUE_INVALID) {
			rc = odp_queue_destroy(entry->out_queue[i].queue);
			_ODP_ASSERT(rc == 0);
			entry->out_queue[i].queue = ODP_QUEUE_INVALID;
		}
	}
}

static void flush_in_queues(pktio_entry_t *entry)
{
	odp_pktin_mode_t mode;
	int num, i;
	int max_pkts = 16;
	odp_packet_t packets[max_pkts];

	mode = entry->param.in_mode;
	num  = entry->num_in_queue;

	if (mode == ODP_PKTIN_MODE_DIRECT) {
		for (i = 0; i < num; i++) {
			int ret;
			odp_pktin_queue_t pktin = entry->in_queue[i].pktin;

			while ((ret = odp_pktin_recv(pktin, packets,
						     max_pkts))) {
				if (ret < 0) {
					_ODP_ERR("Queue flush failed\n");
					return;
				}

				odp_packet_free_multi(packets, ret);
			}
		}
	}
}

int odp_pktio_close(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int res;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_ERR("Bad handle\n");
		return -1;
	}

	if (entry->state == PKTIO_STATE_STARTED) {
		_ODP_DBG("Missing odp_pktio_stop() before close.\n");
		return -1;
	}

	if (entry->state == PKTIO_STATE_STOPPED)
		flush_in_queues(entry);

	lock_entry(entry);

	destroy_in_queues(entry, entry->num_in_queue);
	destroy_out_queues(entry, entry->num_out_queue);

	entry->num_in_queue  = 0;
	entry->num_out_queue = 0;

	if (entry->tx_compl_pool != ODP_POOL_INVALID) {
		if (odp_pool_destroy(entry->tx_compl_pool) == -1) {
			unlock_entry(entry);
			_ODP_ERR("Unable to destroy Tx event completion pool\n");
			return -1;
		}
	}

	if (entry->tx_compl_status_shm != ODP_SHM_INVALID) {
		if (odp_shm_free(entry->tx_compl_status_shm) < 0) {
			unlock_entry(entry);
			_ODP_ERR("Unable to destroy Tx poll completion SHM\n");
			return -1;
		}
	}

	odp_spinlock_lock(&pktio_global->lock);
	res = _pktio_close(entry);
	odp_spinlock_unlock(&pktio_global->lock);
	if (res)
		_ODP_ABORT("unable to close pktio\n");

	unlock_entry(entry);

	_ODP_DBG("interface: %s\n", entry->name);

	return 0;
}

static int configure_tx_event_compl(pktio_entry_t *entry)
{
	odp_pool_param_t params;
	const char *name_base = "_odp_pktio_tx_compl_";
	char pool_name[ODP_POOL_NAME_LEN];

	if (entry->tx_compl_pool != ODP_POOL_INVALID)
		return 0;

	snprintf(pool_name, sizeof(pool_name), "%s%d", name_base, odp_pktio_index(entry->handle));
	odp_pool_param_init(&params);

	params.type = ODP_POOL_BUFFER;
	params.buf.num = pktio_global->config.tx_compl_pool_size;
	params.buf.size = sizeof(_odp_pktio_tx_compl_t);
	entry->tx_compl_pool = odp_pool_create(pool_name, &params);

	if (entry->tx_compl_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static int configure_tx_poll_compl(pktio_entry_t *entry, uint32_t count)
{
	odp_shm_t shm;
	const char *name_base = "_odp_pktio_tx_compl_";
	char shm_name[ODP_SHM_NAME_LEN];

	if (entry->tx_compl_status_shm != ODP_SHM_INVALID)
		return 0;

	snprintf(shm_name, sizeof(shm_name), "%s%d", name_base, odp_pktio_index(entry->handle));
	shm = odp_shm_reserve(shm_name, sizeof(odp_atomic_u32_t) * count, ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID)
		return -1;

	entry->tx_compl_status_shm = shm;
	entry->tx_compl_status = odp_shm_addr(shm);

	if (entry->tx_compl_status == NULL)
		return -1;

	for (uint32_t i = 0; i < count; i++)
		odp_atomic_init_u32(&entry->tx_compl_status[i], 0);

	return 0;
}

int odp_pktio_config(odp_pktio_t hdl, const odp_pktio_config_t *config)
{
	pktio_entry_t *entry;
	odp_pktio_capability_t capa;
	odp_pktio_config_t default_config;
	int res = 0;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		_ODP_ERR("Bad handle\n");
		return -1;
	}

	if (config == NULL) {
		odp_pktio_config_init(&default_config);
		config = &default_config;
	}

	if (odp_pktio_capability(hdl, &capa))
		return -1;

	/* Check config for invalid values */
	if (config->pktin.all_bits & ~capa.config.pktin.all_bits) {
		_ODP_ERR("Unsupported input configuration option\n");
		return -1;
	}
	if (config->pktout.all_bits & ~capa.config.pktout.all_bits) {
		_ODP_ERR("Unsupported output configuration option\n");
		return -1;
	}

	if (config->enable_loop && !capa.config.enable_loop) {
		_ODP_ERR("Loopback mode not supported\n");
		return -1;
	}

	if (config->flow_control.pause_rx != ODP_PKTIO_LINK_PAUSE_OFF ||
	    config->flow_control.pause_tx != ODP_PKTIO_LINK_PAUSE_OFF) {
		_ODP_ERR("Link flow control is not supported\n");
		return -1;
	}

	lock_entry(entry);
	if (entry->state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		_ODP_DBG("pktio %s: not stopped\n", entry->name);
		return -1;
	}

	entry->config = *config;

	entry->enabled.tx_ts = config->pktout.bit.ts_ena;
	entry->enabled.tx_compl = (config->pktout.bit.tx_compl_ena ||
				   config->tx_compl.mode_event ||
				   config->tx_compl.mode_poll);

	if (entry->enabled.tx_compl) {
		if ((config->pktout.bit.tx_compl_ena || config->tx_compl.mode_event) &&
		    configure_tx_event_compl(entry)) {
			unlock_entry(entry);
			_ODP_ERR("Unable to configure Tx event completion\n");
			return -1;
		}

		if (config->tx_compl.mode_poll &&
		    configure_tx_poll_compl(entry, config->tx_compl.max_compl_id + 1)) {
			unlock_entry(entry);
			_ODP_ERR("Unable to configure Tx poll completion\n");
			return -1;
		}
	}

	entry->enabled.tx_aging = config->pktout.bit.aging_ena;

	if (entry->ops->config)
		res = entry->ops->config(entry, config);

	unlock_entry(entry);

	return res;
}

int odp_pktio_start(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int res = 0;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		_ODP_ERR("Bad handle\n");
		return -1;
	}

	lock_entry(entry);
	if (entry->state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		_ODP_ERR("Already started\n");
		return -1;
	}

	if (entry->state == PKTIO_STATE_STOP_PENDING) {
		unlock_entry(entry);
		_ODP_ERR("Scheduled pktio stop pending\n");
		return -1;
	}

	entry->parse_layer = pktio_cls_enabled(entry) ?
				       ODP_PROTO_LAYER_ALL :
				       entry->config.parser.layer;
	if (entry->ops->start)
		res = entry->ops->start(entry);
	if (!res)
		entry->state = PKTIO_STATE_STARTED;

	unlock_entry(entry);

	mode = entry->param.in_mode;

	if (mode == ODP_PKTIN_MODE_SCHED) {
		uint32_t i;
		uint32_t num = entry->num_in_queue;
		int index[num];
		odp_queue_t odpq[num];

		for (i = 0; i < num; i++) {
			index[i] = i;
			odpq[i] = entry->in_queue[i].queue;

			if (entry->in_queue[i].queue == ODP_QUEUE_INVALID) {
				_ODP_ERR("No input queue\n");
				return -1;
			}
		}

		_odp_sched_fn->pktio_start(odp_pktio_index(hdl), num, index, odpq);
	}

	_ODP_DBG("interface: %s, input queues: %u, output queues: %u\n",
		 entry->name, entry->num_in_queue, entry->num_out_queue);

	if (_ODP_PCAPNG) {
		if (_odp_pcapng_start(entry))
			_ODP_ERR("pcapng start failed, won't capture\n");
	}

	return res;
}

static int _pktio_stop(pktio_entry_t *entry)
{
	int res = 0;
	odp_pktin_mode_t mode = entry->param.in_mode;

	if (entry->state != PKTIO_STATE_STARTED) {
		_ODP_ERR("Not started\n");
		return -1;
	}

	if (entry->ops->stop)
		res = entry->ops->stop(entry);

	if (res)
		return -1;

	if (mode == ODP_PKTIN_MODE_SCHED)
		entry->state = PKTIO_STATE_STOP_PENDING;
	else
		entry->state = PKTIO_STATE_STOPPED;

	if (_ODP_PCAPNG)
		_odp_pcapng_stop(entry);

	return res;
}

int odp_pktio_stop(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int res;

	entry = get_pktio_entry(hdl);
	if (!entry) {
		_ODP_ERR("Bad handle\n");
		return -1;
	}

	lock_entry(entry);
	res = _pktio_stop(entry);
	unlock_entry(entry);

	_ODP_DBG("interface: %s\n", entry->name);

	return res;
}

odp_pktio_t odp_pktio_lookup(const char *name)
{
	odp_pktio_t hdl = ODP_PKTIO_INVALID;
	pktio_entry_t *entry;
	const char *ifname;
	int i;

	ifname = strip_pktio_type(name, NULL);

	odp_spinlock_lock(&pktio_global->lock);

	for (i = 0; i < CONFIG_PKTIO_ENTRIES; ++i) {
		entry = pktio_entry_by_index(i);
		if (!entry || is_free(entry))
			continue;

		lock_entry(entry);

		if (entry->state >= PKTIO_STATE_ACTIVE &&
		    strncmp(entry->name, ifname, sizeof(entry->name)) == 0)
			hdl = _odp_cast_scalar(odp_pktio_t, i + 1);

		unlock_entry(entry);

		if (hdl != ODP_PKTIO_INVALID)
			break;
	}

	odp_spinlock_unlock(&pktio_global->lock);

	return hdl;
}

static inline odp_packet_vector_t packet_vector_create(odp_packet_t packets[], uint32_t num,
						       odp_pool_t pool)
{
	odp_packet_vector_t pktv;
	odp_packet_t *pkt_tbl;
	uint32_t i;

	pktv = odp_packet_vector_alloc(pool);
	if (odp_unlikely(pktv == ODP_PACKET_VECTOR_INVALID)) {
		odp_packet_free_multi(packets, num);
		return ODP_PACKET_VECTOR_INVALID;
	}

	odp_packet_vector_tbl(pktv, &pkt_tbl);
	for (i = 0; i < num; i++)
		pkt_tbl[i] = packets[i];
	odp_packet_vector_size_set(pktv, num);

	return pktv;
}

static inline int pktin_recv_buf(pktio_entry_t *entry, int pktin_index,
				 _odp_event_hdr_t *event_hdrs[], int num)
{
	const odp_bool_t vector_enabled = entry->in_queue[pktin_index].vector.enable;
	odp_pool_t pool = ODP_POOL_INVALID;
	int num_rx;

	if (vector_enabled) {
		/* Make sure all packets will fit into a single packet vector */
		if ((int)entry->in_queue[pktin_index].vector.max_size < num)
			num = entry->in_queue[pktin_index].vector.max_size;
		pool = entry->in_queue[pktin_index].vector.pool;
	}

	num_rx = entry->ops->recv(entry, pktin_index, (odp_packet_t *)event_hdrs, num);

	if (!vector_enabled || num_rx < 2)
		return num_rx;

	odp_packet_vector_t pktv = packet_vector_create((odp_packet_t *)event_hdrs, num_rx, pool);

	if (odp_unlikely(pktv == ODP_PACKET_VECTOR_INVALID))
		return 0;

	event_hdrs[0] = _odp_packet_vector_to_event_hdr(pktv);
	return 1;
}

static int pktout_enqueue(odp_queue_t queue, _odp_event_hdr_t *event_hdr)
{
	odp_packet_t pkt = packet_from_event_hdr(event_hdr);
	int nbr;

	_ODP_ASSERT(odp_event_type(_odp_event_from_hdr(event_hdr)) == ODP_EVENT_PACKET);

	if (_odp_sched_fn->ord_enq_multi(queue, (void **)event_hdr, 1, &nbr))
		return (nbr == 1 ? 0 : -1);

	nbr = odp_pktout_send(_odp_queue_fn->get_pktout(queue), &pkt, 1);
	return (nbr == 1 ? 0 : -1);
}

static int pktout_enq_multi(odp_queue_t queue, _odp_event_hdr_t *event_hdr[],
			    int num)
{
	int nbr;

	if (ODP_DEBUG) {
		for (int i = 0; i < num; i++)
			_ODP_ASSERT(odp_event_type(_odp_event_from_hdr(event_hdr[i])) ==
				    ODP_EVENT_PACKET);
	}

	if (_odp_sched_fn->ord_enq_multi(queue, (void **)event_hdr, num, &nbr))
		return nbr;

	return odp_pktout_send(_odp_queue_fn->get_pktout(queue), (odp_packet_t *)event_hdr, num);
}

static _odp_event_hdr_t *pktin_dequeue(odp_queue_t queue)
{
	_odp_event_hdr_t *event_hdr;
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	int pkts;
	odp_pktin_queue_t pktin_queue = _odp_queue_fn->get_pktin(queue);
	odp_pktio_t pktio = pktin_queue.pktio;
	int pktin_index   = pktin_queue.index;
	pktio_entry_t *entry = get_pktio_entry(pktio);

	_ODP_ASSERT(entry != NULL);

	if (_odp_queue_fn->orig_deq_multi(queue, &event_hdr, 1) == 1)
		return event_hdr;

	if (odp_unlikely(entry->state != PKTIO_STATE_STARTED))
		return 0;

	pkts = pktin_recv_buf(entry, pktin_index, hdr_tbl, QUEUE_MULTI_MAX);

	if (pkts <= 0)
		return NULL;

	if (pkts > 1) {
		int num_enq;
		int num = pkts - 1;

		num_enq = odp_queue_enq_multi(queue,
					      (odp_event_t *)&hdr_tbl[1], num);

		if (odp_unlikely(num_enq < num)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			_ODP_DBG("Interface %s dropped %i packets\n", entry->name, num - num_enq);
			_odp_event_free_multi(&hdr_tbl[num_enq + 1], num - num_enq);
		}
	}

	event_hdr = hdr_tbl[0];
	return event_hdr;
}

static int pktin_deq_multi(odp_queue_t queue, _odp_event_hdr_t *event_hdr[],
			   int num)
{
	int nbr;
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	int pkts, i, j;
	odp_pktin_queue_t pktin_queue = _odp_queue_fn->get_pktin(queue);
	odp_pktio_t pktio = pktin_queue.pktio;
	int pktin_index   = pktin_queue.index;
	pktio_entry_t *entry = get_pktio_entry(pktio);

	_ODP_ASSERT(entry != NULL);

	nbr = _odp_queue_fn->orig_deq_multi(queue, event_hdr, num);
	if (odp_unlikely(nbr > num))
		_ODP_ABORT("queue_deq_multi req: %d, returned %d\n", num, nbr);

	/** queue already has number of requested buffers,
	 *  do not do receive in that case.
	 */
	if (nbr == num || odp_unlikely(entry->state != PKTIO_STATE_STARTED))
		return nbr;

	pkts = pktin_recv_buf(entry, pktin_index, hdr_tbl, QUEUE_MULTI_MAX);

	if (pkts <= 0)
		return nbr;

	for (i = 0; i < pkts && nbr < num; i++, nbr++)
		event_hdr[nbr] = hdr_tbl[i];

	/* Queue the rest for later */
	for (j = 0; i < pkts; i++, j++)
		hdr_tbl[j] = hdr_tbl[i];

	if (j) {
		int num_enq;

		num_enq = odp_queue_enq_multi(queue, (odp_event_t *)hdr_tbl, j);

		if (odp_unlikely(num_enq < j)) {
			if (odp_unlikely(num_enq < 0))
				num_enq = 0;

			_ODP_DBG("Interface %s dropped %i packets\n",
				 entry->name, j - num_enq);
			_odp_event_free_multi(&event_hdr[num_enq], j - num_enq);
		}
	}

	return nbr;
}

int _odp_sched_cb_pktin_poll(int pktio_index, int pktin_index,
			     _odp_event_hdr_t *hdr_tbl[], int num)
{
	pktio_entry_t *entry = pktio_entry_by_index(pktio_index);
	int state = entry->state;

	if (odp_unlikely(state != PKTIO_STATE_STARTED)) {
		if (state < PKTIO_STATE_ACTIVE ||
		    state == PKTIO_STATE_STOP_PENDING)
			return -1;

		_ODP_DBG("Interface %s not started\n", entry->name);
		return 0;
	}

	return pktin_recv_buf(entry, pktin_index, hdr_tbl, num);
}

void _odp_sched_cb_pktio_stop_finalize(int pktio_index)
{
	int state;
	pktio_entry_t *entry = pktio_entry_by_index(pktio_index);

	lock_entry(entry);

	state = entry->state;

	if (state != PKTIO_STATE_STOP_PENDING &&
	    state != PKTIO_STATE_CLOSE_PENDING) {
		unlock_entry(entry);
		_ODP_ERR("Not in a pending state %i\n", state);
		return;
	}

	if (state == PKTIO_STATE_STOP_PENDING)
		entry->state = PKTIO_STATE_STOPPED;
	else
		entry->state = PKTIO_STATE_FREE;

	unlock_entry(entry);
}

static inline uint32_t pktio_maxlen(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	uint32_t ret = 0;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return 0;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return 0;
	}

	if (entry->ops->maxlen_get)
		ret = entry->ops->maxlen_get(entry);

	unlock_entry(entry);
	return ret;
}

uint32_t odp_pktin_maxlen(odp_pktio_t pktio)
{
	return pktio_maxlen(pktio);
}

uint32_t odp_pktout_maxlen(odp_pktio_t pktio)
{
	return pktio_maxlen(pktio);
}

int odp_pktio_maxlen_set(odp_pktio_t hdl, uint32_t maxlen_input,
			 uint32_t maxlen_output)
{
	odp_pktio_capability_t capa;
	pktio_entry_t *entry;
	int ret = 0;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_ERR("Pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	ret = odp_pktio_capability(hdl, &capa);
	if (ret) {
		_ODP_ERR("Reading pktio capability failed\n");
		goto fail;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		_ODP_ERR("Pktio already freed\n");
		ret = -1;
		goto fail;
	}
	if (entry->state == PKTIO_STATE_STARTED) {
		_ODP_ERR("Pktio not stopped\n");
		ret = -1;
		goto fail;
	}

	if (capa.set_op.op.maxlen == 0) {
		_ODP_ERR("Setting maximum frame length not supported\n");
		ret = -1;
		goto fail;
	}

	if (capa.maxlen.equal && (maxlen_input != maxlen_output)) {
		_ODP_ERR("Max input and output lengths don't match\n");
		ret = -1;
		goto fail;
	}

	if (maxlen_input < capa.maxlen.min_input ||
	    maxlen_input > capa.maxlen.max_input) {
		_ODP_ERR("Invalid max input length value: %" PRIu32 "\n", maxlen_input);
		ret = -1;
		goto fail;
	}

	if (maxlen_output < capa.maxlen.min_output ||
	    maxlen_output > capa.maxlen.max_output) {
		_ODP_ERR("Invalid max output length value: %" PRIu32 "\n", maxlen_output);
		ret = -1;
		goto fail;
	}

	if (entry->ops->maxlen_set)
		ret = entry->ops->maxlen_set(entry, maxlen_input, maxlen_output);

fail:
	unlock_entry(entry);
	return ret;
}

int odp_pktio_promisc_mode_set(odp_pktio_t hdl, odp_bool_t enable)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}
	if (entry->state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		return -1;
	}

	if (entry->ops->promisc_mode_set)
		ret = entry->ops->promisc_mode_set(entry, enable);

	unlock_entry(entry);
	return ret;
}

int odp_pktio_promisc_mode(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->ops->promisc_mode_get)
		ret = entry->ops->promisc_mode_get(entry);
	unlock_entry(entry);

	return ret;
}

int odp_pktio_mac_addr(odp_pktio_t hdl, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	int ret = ETH_ALEN;

	if (addr_size < ETH_ALEN) {
		/* Output buffer too small */
		return -1;
	}

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->ops->mac_get) {
		ret = entry->ops->mac_get(entry, mac_addr);
	} else {
		_ODP_DBG("pktio does not support mac addr get\n");
		ret = -1;
	}
	unlock_entry(entry);

	return ret;
}

int odp_pktio_mac_addr_set(odp_pktio_t hdl, const void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	int ret = -1;

	if (addr_size < ETH_ALEN) {
		/* Input buffer too small */
		return -1;
	}

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->state == PKTIO_STATE_STARTED) {
		unlock_entry(entry);
		return -1;
	}

	if (entry->ops->mac_set)
		ret = entry->ops->mac_set(entry, mac_addr);

	unlock_entry(entry);
	return ret;
}

odp_pktio_link_status_t odp_pktio_link_status(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	int ret = ODP_PKTIO_LINK_STATUS_UNKNOWN;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return ODP_PKTIO_LINK_STATUS_UNKNOWN;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return ODP_PKTIO_LINK_STATUS_UNKNOWN;
	}

	if (entry->ops->link_status)
		ret = entry->ops->link_status(entry);
	unlock_entry(entry);

	return ret;
}

void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
	params->in_mode  = ODP_PKTIN_MODE_DIRECT;
	params->out_mode = ODP_PKTOUT_MODE_DIRECT;
}

void odp_pktin_queue_param_init(odp_pktin_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktin_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
	/* no need to choose queue type since pktin mode defines it */
	odp_queue_param_init(&param->queue_param);
}

void odp_pktout_queue_param_init(odp_pktout_queue_param_t *param)
{
	memset(param, 0, sizeof(odp_pktout_queue_param_t));
	param->op_mode = ODP_PKTIO_OP_MT;
	param->num_queues = 1;
}

void odp_pktio_config_init(odp_pktio_config_t *config)
{
	memset(config, 0, sizeof(odp_pktio_config_t));

	config->parser.layer = ODP_PROTO_LAYER_ALL;
	config->reassembly.max_num_frags = 2;
	config->flow_control.pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	config->flow_control.pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
}

int odp_pktio_info(odp_pktio_t hdl, odp_pktio_info_t *info)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_info_t));
	info->name = entry->full_name;
	info->drv_name = entry->ops->name;
	info->pool = entry->pool;
	memcpy(&info->param, &entry->param, sizeof(odp_pktio_param_t));

	return 0;
}

int odp_pktio_link_info(odp_pktio_t hdl, odp_pktio_link_info_t *info)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	if (entry->ops->link_info)
		return entry->ops->link_info(entry, info);

	return -1;
}

uint64_t odp_pktio_ts_res(odp_pktio_t hdl)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return 0;
	}

	if (entry->ops->pktio_ts_res)
		return entry->ops->pktio_ts_res(entry);

	return odp_time_global_res();
}

odp_time_t odp_pktio_ts_from_ns(odp_pktio_t hdl, uint64_t ns)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(hdl);

	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return ODP_TIME_NULL;
	}

	if (entry->ops->pktio_ts_from_ns)
		return entry->ops->pktio_ts_from_ns(entry, ns);

	return odp_time_global_from_ns(ns);
}

odp_time_t odp_pktio_time(odp_pktio_t hdl, odp_time_t *global_ts)
{
	pktio_entry_t *entry;
	odp_time_t ts;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return ODP_TIME_NULL;
	}

	/* Callback if present */
	if (entry->ops->pktio_time)
		return entry->ops->pktio_time(entry, global_ts);

	/* By default both Packet IO time source and
	 * global time source are same.
	 */
	ts = odp_time_global();
	if (global_ts)
		*global_ts = ts;
	return ts;
}

void odp_pktio_print(odp_pktio_t hdl)
{
	pktio_entry_t *entry;
	odp_pktio_capability_t capa;
	uint8_t addr[ETH_ALEN];
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;

	entry = get_pktio_entry(hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return;
	}

	len += snprintf(&str[len], n - len, "Pktio info\n----------\n");
	len += snprintf(&str[len], n - len,
			"  name              %s\n", entry->name);
	len += snprintf(&str[len], n - len,
			"  type              %s\n", entry->ops->name);
	len += snprintf(&str[len], n - len,
			"  index             %i\n", odp_pktio_index(hdl));
	len += snprintf(&str[len], n - len,
			"  handle            0x%" PRIx64 "\n",
			odp_pktio_to_u64(hdl));
	len += snprintf(&str[len], n - len,
			"  pool handle       0x%" PRIx64 "\n",
			odp_pool_to_u64(entry->pool));
	len += snprintf(&str[len], n - len,
			"  state             %s\n",
			entry->state ==  PKTIO_STATE_STARTED ? "start" :
		       (entry->state ==  PKTIO_STATE_STOPPED ? "stop" :
		       (entry->state ==  PKTIO_STATE_STOP_PENDING ?
			"stop pending" :
		       (entry->state ==  PKTIO_STATE_OPENED ? "opened" :
							      "unknown"))));
	memset(addr, 0, sizeof(addr));
	odp_pktio_mac_addr(hdl, addr, ETH_ALEN);
	len += snprintf(&str[len], n - len,
			"  mac               %02x:%02x:%02x:%02x:%02x:%02x\n",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	len += snprintf(&str[len], n - len,
			"  pktin maxlen      %" PRIu32 "\n",
			odp_pktin_maxlen(hdl));
	len += snprintf(&str[len], n - len,
			"  pktout maxlen     %" PRIu32 "\n",
			odp_pktout_maxlen(hdl));
	len += snprintf(&str[len], n - len,
			"  promisc           %s\n",
			odp_pktio_promisc_mode(hdl) ? "yes" : "no");

	if (!odp_pktio_capability(hdl, &capa)) {
		len += snprintf(&str[len], n - len, "  max input queues  %u\n",
				capa.max_input_queues);
		len += snprintf(&str[len], n - len, "  max output queues %u\n",
				capa.max_output_queues);
	}

	str[len] = '\0';

	_ODP_PRINT("\n%s", str);

	if (entry->ops->print)
		entry->ops->print(entry);

	_ODP_PRINT("\n");
}

int _odp_pktio_term_global(void)
{
	odp_shm_t shm;
	int i, pktio_if;
	int ret = 0;

	if (pktio_global == NULL)
		return 0;

	for (i = 0; i < CONFIG_PKTIO_ENTRIES; ++i) {
		pktio_entry_t *pktio_entry;

		pktio_entry = &pktio_global->entries[i];

		if (is_free(pktio_entry))
			continue;

		lock_entry(pktio_entry);
		if (pktio_entry->state == PKTIO_STATE_STARTED) {
			ret = _pktio_stop(pktio_entry);
			if (ret)
				_ODP_ABORT("unable to stop pktio %s\n", pktio_entry->name);
		}

		if (pktio_entry->state != PKTIO_STATE_CLOSE_PENDING)
			ret = _pktio_close(pktio_entry);
		if (ret)
			_ODP_ABORT("unable to close pktio %s\n", pktio_entry->name);
		unlock_entry(pktio_entry);
	}

	for (pktio_if = 0; _odp_pktio_if_ops[pktio_if]; ++pktio_if) {
		if (_odp_pktio_if_ops[pktio_if]->term)
			if (_odp_pktio_if_ops[pktio_if]->term())
				_ODP_ABORT("failed to terminate pktio type %d", pktio_if);
	}

	if (_ODP_PCAPNG) {
		ret = _odp_pcapng_term_global();
		if (ret)
			_ODP_ERR("Failed to terminate pcapng\n");
	}

	shm = pktio_global->shm;
	ret = odp_shm_free(shm);
	if (ret != 0)
		_ODP_ERR("shm free failed\n");

	return ret;
}

int odp_pktio_capability(odp_pktio_t pktio, odp_pktio_capability_t *capa)
{
	pktio_entry_t *entry;
	int ret;
	uint32_t mtu;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	ret = entry->ops->capability(entry, capa);

	if (ret) {
		_ODP_ERR("Driver specific capa query failed: %s\n", entry->name);
		return -1;
	}

	mtu = pktio_maxlen(pktio);

	if (mtu == 0) {
		_ODP_ERR("MTU query failed: %s\n", entry->name);
		return -1;
	}

	/* The same parser is used for all pktios */
	capa->config.parser.layer = ODP_PROTO_LAYER_ALL;
	/* Header skip is not supported */
	capa->set_op.op.skip_offset = 0;
	/* Irrespective of whether we optimize the fast path or not,
	 * we can report that it is supported.
	 */
	capa->config.pktout.bit.no_packet_refs = 1;

	/* LSO implementation is common to all pktios */
	capa->lso.max_profiles           = PKTIO_LSO_PROFILES;
	capa->lso.max_profiles_per_pktio = PKTIO_LSO_PROFILES;
	capa->lso.max_packet_segments    = PKT_MAX_SEGS;
	capa->lso.max_segments           = PKTIO_LSO_MAX_SEGMENTS;
	capa->lso.max_payload_len        = mtu - PKTIO_LSO_MIN_PAYLOAD_OFFSET;
	capa->lso.max_payload_offset     = PKTIO_LSO_MAX_PAYLOAD_OFFSET;
	capa->lso.max_num_custom         = ODP_LSO_MAX_CUSTOM;
	capa->lso.proto.ipv4             = 1;
	capa->lso.proto.custom           = 1;
	capa->lso.mod_op.add_segment_num = 1;

	capa->tx_compl.queue_type_sched = 1;
	capa->tx_compl.queue_type_plain = 1;
	capa->tx_compl.max_compl_id = UINT32_MAX - 1;

	capa->config.pktout.bit.aging_ena = 1;
	capa->max_tx_aging_tmo_ns = MAX_TX_AGING_TMO_NS;

	/* Packet vector generation is common for all pktio types */
	if (entry->param.in_mode ==  ODP_PKTIN_MODE_QUEUE ||
	    entry->param.in_mode ==  ODP_PKTIN_MODE_SCHED) {
		capa->vector.supported = ODP_SUPPORT_YES;
		capa->vector.max_size = CONFIG_PACKET_VECTOR_MAX_SIZE;
		capa->vector.min_size = 1;
		capa->vector.max_tmo_ns = 0;
		capa->vector.min_tmo_ns = 0;
	}

	capa->reassembly.ip = false;
	capa->reassembly.ipv4 = false;
	capa->reassembly.ipv6 = false;
	capa->flow_control.pause_rx = 0;
	capa->flow_control.pfc_rx = 0;
	capa->flow_control.pause_tx = 0;
	capa->flow_control.pfc_tx = 0;

	return 0;
}

ODP_STATIC_ASSERT(CONFIG_PKTIO_ENTRIES - 1 <= ODP_PKTIO_MAX_INDEX,
		  "CONFIG_PKTIO_ENTRIES larger than ODP_PKTIO_MAX_INDEX");

unsigned int odp_pktio_max_index(void)
{
	return CONFIG_PKTIO_ENTRIES - 1;
}

int odp_pktio_stats(odp_pktio_t pktio,
		    odp_pktio_stats_t *stats)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}

	if (entry->ops->stats)
		ret = entry->ops->stats(entry, stats);
	if (odp_likely(ret == 0)) {
		stats->in_discards += odp_atomic_load_u64(&entry->stats_extra.in_discards);
		stats->in_errors += odp_atomic_load_u64(&entry->stats_extra.in_errors);
		stats->out_discards += odp_atomic_load_u64(&entry->stats_extra.out_discards);
	}
	unlock_entry(entry);

	return ret;
}

int odp_pktio_stats_reset(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_DBG("already freed pktio\n");
		return -1;
	}

	odp_atomic_store_u64(&entry->stats_extra.in_discards, 0);
	odp_atomic_store_u64(&entry->stats_extra.in_errors, 0);
	odp_atomic_store_u64(&entry->stats_extra.out_discards, 0);
	if (entry->ops->stats)
		ret = entry->ops->stats_reset(entry);
	unlock_entry(entry);

	return ret;
}

int odp_pktin_queue_stats(odp_pktin_queue_t queue,
			  odp_pktin_queue_stats_t *stats)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int ret = -1;

	entry = get_pktio_entry(queue.pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)queue.pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("pktio entry already freed\n");
		return -1;
	}

	mode = entry->param.in_mode;
	if (odp_unlikely(mode != ODP_PKTIN_MODE_DIRECT)) {
		unlock_entry(entry);
		_ODP_ERR("invalid packet input mode: %d\n", mode);
		return -1;
	}

	if (entry->ops->pktin_queue_stats)
		ret = entry->ops->pktin_queue_stats(entry, queue.index, stats);

	unlock_entry(entry);

	return ret;
}

int odp_pktin_event_queue_stats(odp_pktio_t pktio, odp_queue_t queue,
				odp_pktin_queue_stats_t *stats)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	odp_pktin_queue_t pktin_queue;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("pktio entry already freed\n");
		return -1;
	}

	mode = entry->param.in_mode;
	if (odp_unlikely(mode != ODP_PKTIN_MODE_SCHED && mode != ODP_PKTIN_MODE_QUEUE)) {
		unlock_entry(entry);
		_ODP_ERR("invalid packet input mode: %d\n", mode);
		return -1;
	}

	pktin_queue = _odp_queue_fn->get_pktin(queue);

	if (entry->ops->pktin_queue_stats)
		ret = entry->ops->pktin_queue_stats(entry, pktin_queue.index, stats);

	unlock_entry(entry);

	return ret;
}

int odp_pktout_queue_stats(odp_pktout_queue_t queue,
			   odp_pktout_queue_stats_t *stats)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int ret = -1;

	entry = get_pktio_entry(queue.pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)queue.pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("pktio entry already freed\n");
		return -1;
	}

	mode = entry->param.out_mode;
	if (odp_unlikely(mode != ODP_PKTOUT_MODE_DIRECT)) {
		unlock_entry(entry);
		_ODP_ERR("invalid packet output mode: %d\n", mode);
		return -1;
	}

	if (entry->ops->pktout_queue_stats)
		ret = entry->ops->pktout_queue_stats(entry, queue.index, stats);

	unlock_entry(entry);

	return ret;
}

int odp_pktout_event_queue_stats(odp_pktio_t pktio, odp_queue_t queue,
				 odp_pktout_queue_stats_t *stats)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	odp_pktout_queue_t pktout_queue;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("pktio entry already freed\n");
		return -1;
	}

	mode = entry->param.out_mode;
	if (odp_unlikely(mode != ODP_PKTOUT_MODE_QUEUE)) {
		unlock_entry(entry);
		_ODP_ERR("invalid packet output mode: %d\n", mode);
		return -1;
	}

	pktout_queue = _odp_queue_fn->get_pktout(queue);

	if (entry->ops->pktout_queue_stats)
		ret = entry->ops->pktout_queue_stats(entry, pktout_queue.index, stats);

	unlock_entry(entry);

	return ret;
}

int odp_pktio_extra_stat_info(odp_pktio_t pktio,
			      odp_pktio_extra_stat_info_t info[], int num)
{
	pktio_entry_t *entry;
	int ret = 0;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("already freed pktio\n");
		return -1;
	}

	if (entry->ops->extra_stat_info)
		ret = entry->ops->extra_stat_info(entry, info, num);

	unlock_entry(entry);

	return ret;
}

int odp_pktio_extra_stats(odp_pktio_t pktio, uint64_t stats[], int num)
{
	pktio_entry_t *entry;
	int ret = 0;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("already freed pktio\n");
		return -1;
	}

	if (entry->ops->extra_stats)
		ret = entry->ops->extra_stats(entry, stats, num);

	unlock_entry(entry);

	return ret;
}

int odp_pktio_extra_stat_counter(odp_pktio_t pktio, uint32_t id, uint64_t *stat)
{
	pktio_entry_t *entry;
	int ret = -1;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		_ODP_ERR("already freed pktio\n");
		return -1;
	}

	if (entry->ops->extra_stat_counter)
		ret = entry->ops->extra_stat_counter(entry, id, stat);

	unlock_entry(entry);

	return ret;
}

void odp_pktio_extra_stats_print(odp_pktio_t pktio)
{
	int num_info, num_stats, i;

	num_info = odp_pktio_extra_stat_info(pktio, NULL, 0);
	if (num_info <= 0)
		return;

	num_stats = odp_pktio_extra_stats(pktio, NULL, 0);
	if (num_stats <= 0)
		return;

	if (num_info != num_stats) {
		_ODP_ERR("extra statistics info counts not matching\n");
		return;
	}

	odp_pktio_extra_stat_info_t stats_info[num_stats];
	uint64_t extra_stats[num_stats];

	num_info = odp_pktio_extra_stat_info(pktio, stats_info, num_stats);
	if (num_info <= 0)
		return;

	num_stats = odp_pktio_extra_stats(pktio, extra_stats, num_stats);
	if (num_stats <= 0)
		return;

	if (num_info != num_stats) {
		_ODP_ERR("extra statistics info counts not matching\n");
		return;
	}

	_ODP_PRINT("Pktio extra statistics\n----------------------\n");
	for (i = 0; i < num_stats; i++)
		_ODP_PRINT("  %s=%" PRIu64 "\n", stats_info[i].name, extra_stats[i]);
	_ODP_PRINT("\n");
}

int odp_pktin_queue_config(odp_pktio_t pktio, const odp_pktin_queue_param_t *param)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	odp_pktio_capability_t capa;
	uint32_t num_queues, i;
	int rc;
	odp_queue_t queue;
	odp_pktin_queue_param_t default_param, local_param;

	if (param == NULL) {
		odp_pktin_queue_param_init(&default_param);
		param = &default_param;
	}

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (entry->state == PKTIO_STATE_STARTED) {
		_ODP_ERR("pktio %s: not stopped\n", entry->name);
		return -1;
	}

	mode = entry->param.in_mode;

	/* Ignore the call when packet input is disabled. */
	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (!param->classifier_enable && param->num_queues == 0) {
		_ODP_ERR("invalid num_queues for operation mode\n");
		return -1;
	}

	if (param->classifier_enable) {
		num_queues = 1;

		if (param->num_queues != num_queues) {
			/* When classifier is enabled, ensure that only one input queue will be
			 * configured by driver. */
			memcpy(&local_param, param, sizeof(odp_pktin_queue_param_t));
			local_param.num_queues = num_queues;
			param = &local_param;
		}
	} else {
		num_queues = param->num_queues;
	}

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		_ODP_ERR("pktio %s: unable to read capabilities\n", entry->name);
		return -1;
	}

	entry->enabled.cls = !!param->classifier_enable;

	if (num_queues > capa.max_input_queues) {
		_ODP_ERR("pktio %s: too many input queues\n", entry->name);
		return -1;
	}

	/* Check input queue sizes in direct mode */
	for (i = 0; i < num_queues && mode == ODP_PKTIN_MODE_DIRECT; i++) {
		uint32_t queue_size = param->queue_size[i];

		if (queue_size == 0)
			continue;

		if (capa.max_input_queue_size == 0) {
			_ODP_ERR("pktio %s: configuring input queue size not supported\n",
				 entry->name);
			return -1;
		}
		if (queue_size < capa.min_input_queue_size) {
			_ODP_ERR("pktio %s: input queue size too small\n", entry->name);
			return -1;
		}
		if (queue_size > capa.max_input_queue_size) {
			_ODP_ERR("pktio %s: input queue size too large\n", entry->name);
			return -1;
		}
	}

	/* Validate packet vector parameters */
	if (param->vector.enable) {
		odp_pool_t pool = param->vector.pool;
		odp_pool_info_t pool_info;

		if (mode == ODP_PKTIN_MODE_DIRECT) {
			_ODP_ERR("packet vectors not supported with ODP_PKTIN_MODE_DIRECT\n");
			return -1;
		}
		if (param->vector.max_size < capa.vector.min_size) {
			_ODP_ERR("vector.max_size too small %" PRIu32 "\n",
				 param->vector.max_size);
			return -1;
		}
		if (param->vector.max_size > capa.vector.max_size) {
			_ODP_ERR("vector.max_size too large %" PRIu32 "\n",
				 param->vector.max_size);
			return -1;
		}
		if (param->vector.max_tmo_ns > capa.vector.max_tmo_ns) {
			_ODP_ERR("vector.max_tmo_ns too large %" PRIu64 "\n",
				 param->vector.max_tmo_ns);
			return -1;
		}

		if (pool == ODP_POOL_INVALID || odp_pool_info(pool, &pool_info)) {
			_ODP_ERR("invalid packet vector pool\n");
			return -1;
		}
		if (pool_info.params.type != ODP_POOL_VECTOR) {
			_ODP_ERR("wrong pool type\n");
			return -1;
		}
		if (param->vector.max_size > pool_info.params.vector.max_size) {
			_ODP_ERR("vector.max_size larger than pool max vector size\n");
			return -1;
		}
	}

	/* If re-configuring, destroy old queues */
	if (entry->num_in_queue)
		destroy_in_queues(entry, entry->num_in_queue);

	for (i = 0; i < num_queues; i++) {
		if (mode == ODP_PKTIN_MODE_QUEUE ||
		    mode == ODP_PKTIN_MODE_SCHED) {
			odp_queue_param_t queue_param;
			char name[ODP_QUEUE_NAME_LEN];
			int pktio_id = odp_pktio_index(pktio);
			odp_pktin_queue_param_ovr_t *queue_param_ovr = NULL;

			if (param->queue_param_ovr)
				queue_param_ovr = param->queue_param_ovr + i;

			snprintf(name, sizeof(name), "odp-pktin-%i-%i",
				 pktio_id, i);

			if (param->classifier_enable) {
				odp_queue_param_init(&queue_param);
			} else {
				memcpy(&queue_param, &param->queue_param,
				       sizeof(odp_queue_param_t));
				if (queue_param_ovr)
					queue_param.sched.group =
						queue_param_ovr->group;
			}

			queue_param.type = ODP_QUEUE_TYPE_PLAIN;

			if (mode == ODP_PKTIN_MODE_SCHED)
				queue_param.type = ODP_QUEUE_TYPE_SCHED;

			queue = odp_queue_create(name, &queue_param);

			if (queue == ODP_QUEUE_INVALID) {
				_ODP_ERR("pktio %s: event queue create failed\n", entry->name);
				destroy_in_queues(entry, i + 1);
				return -1;
			}

			_odp_queue_fn->set_pktin(queue, pktio, i);
			if (mode == ODP_PKTIN_MODE_QUEUE)
				_odp_queue_fn->set_enq_deq_fn(queue,
							      NULL,
							      NULL,
							      pktin_dequeue,
							      pktin_deq_multi);

			entry->in_queue[i].queue = queue;

		} else {
			entry->in_queue[i].queue = ODP_QUEUE_INVALID;
		}

		entry->in_queue[i].pktin.index = i;
		entry->in_queue[i].pktin.pktio = entry->handle;
		entry->in_queue[i].vector = param->vector;
	}

	entry->num_in_queue = num_queues;

	if (entry->ops->input_queues_config)
		return entry->ops->input_queues_config(entry, param);

	return 0;
}

int _odp_pktio_pktout_tm_config(odp_pktio_t pktio_hdl,
				odp_pktout_queue_t *queue, bool reconf)
{
	odp_pktout_queue_param_t param;
	bool pktio_started = false;
	odp_pktout_mode_t mode;
	pktio_entry_t *entry;
	uint32_t i;
	int rc;

	odp_pktout_queue_param_init(&param);
	param.num_queues = 1;

	entry = get_pktio_entry(pktio_hdl);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio_hdl);
		return -1;
	}

	mode = entry->param.out_mode;
	/* Don't proceed further if mode is not TM */
	if (mode != ODP_PKTOUT_MODE_TM)
		return -1;

	/* Don't reconfigure unless requested */
	if (entry->num_out_queue && !reconf) {
		*queue = entry->out_queue[0].pktout;
		return 0;
	}

	if (entry->state == PKTIO_STATE_STARTED) {
		pktio_started = true;
		rc = odp_pktio_stop(pktio_hdl);
		if (rc) {
			_ODP_ERR("Unable to stop pktio, rc=%d\n", rc);
			return rc;
		}
	}

	/* If re-configuring, destroy old queues */
	if (entry->num_out_queue) {
		destroy_out_queues(entry, entry->num_out_queue);
		entry->num_out_queue = 0;
	}

	init_out_queues(entry);
	for (i = 0; i < param.num_queues; i++) {
		entry->out_queue[i].pktout.index = i;
		entry->out_queue[i].pktout.pktio = pktio_hdl;
	}

	entry->num_out_queue = param.num_queues;

	rc = 0;
	if (entry->ops->output_queues_config) {
		rc = entry->ops->output_queues_config(entry, &param);
		if (rc)
			_ODP_ERR("Unable to setup output queues, rc=%d\n", rc);
	}

	/* Return pktout queue on success */
	if (!rc)
		*queue = entry->out_queue[0].pktout;

	/* Take pktio back to its previous state */
	if (pktio_started)
		rc |= odp_pktio_start(pktio_hdl);
	return rc;
}

int odp_pktout_queue_config(odp_pktio_t pktio,
			    const odp_pktout_queue_param_t *param)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	odp_pktio_capability_t capa;
	uint32_t num_queues, i;
	int rc;
	odp_pktout_queue_param_t default_param;

	if (param == NULL) {
		odp_pktout_queue_param_init(&default_param);
		param = &default_param;
	}

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (entry->state == PKTIO_STATE_STARTED) {
		_ODP_ERR("pktio %s: not stopped\n", entry->name);
		return -1;
	}

	mode = entry->param.out_mode;

	/* Ignore the call when packet output is disabled, or routed through
	 * traffic manager. */
	if (mode == ODP_PKTOUT_MODE_DISABLED || mode == ODP_PKTOUT_MODE_TM)
		return 0;

	if (mode != ODP_PKTOUT_MODE_DIRECT && mode != ODP_PKTOUT_MODE_QUEUE) {
		_ODP_ERR("pktio %s: bad packet output mode\n", entry->name);
		return -1;
	}

	num_queues = param->num_queues;

	if (num_queues == 0) {
		_ODP_ERR("pktio %s: zero output queues\n", entry->name);
		return -1;
	}

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		_ODP_ERR("pktio %s: unable to read capabilities\n", entry->name);
		return -1;
	}

	if (num_queues > capa.max_output_queues) {
		_ODP_ERR("pktio %s: too many output queues\n", entry->name);
		return -1;
	}

	/* Check output queue sizes */
	for (i = 0; i < num_queues; i++) {
		uint32_t queue_size = param->queue_size[i];

		if (queue_size == 0)
			continue;

		if (capa.max_output_queue_size == 0) {
			_ODP_ERR("pktio %s: configuring output queue size not supported\n",
				 entry->name);
			return -1;
		}
		if (queue_size < capa.min_output_queue_size) {
			_ODP_ERR("pktio %s: output queue size too small\n", entry->name);
			return -1;
		}
		if (queue_size > capa.max_output_queue_size) {
			_ODP_ERR("pktio %s: output queue size too large\n", entry->name);
			return -1;
		}
	}

	/* If re-configuring, destroy old queues */
	if (entry->num_out_queue) {
		destroy_out_queues(entry, entry->num_out_queue);
		entry->num_out_queue = 0;
	}

	init_out_queues(entry);

	for (i = 0; i < num_queues; i++) {
		entry->out_queue[i].pktout.index = i;
		entry->out_queue[i].pktout.pktio = pktio;
	}

	entry->num_out_queue = num_queues;

	if (mode == ODP_PKTOUT_MODE_QUEUE) {
		for (i = 0; i < num_queues; i++) {
			odp_queue_t queue;
			odp_queue_param_t queue_param;
			char name[ODP_QUEUE_NAME_LEN];
			int pktio_id = odp_pktio_index(pktio);

			snprintf(name, sizeof(name), "odp-pktout-%i-%i",
				 pktio_id, i);

			odp_queue_param_init(&queue_param);
			/* Application cannot dequeue from the queue */
			queue_param.deq_mode = ODP_QUEUE_OP_DISABLED;

			queue = odp_queue_create(name, &queue_param);

			if (queue == ODP_QUEUE_INVALID) {
				_ODP_ERR("pktout %s: event queue create failed\n", entry->name);
				destroy_out_queues(entry, i + 1);
				return -1;
			}

			_odp_queue_fn->set_pktout(queue, pktio, i);

			/* Override default enqueue / dequeue functions */
			_odp_queue_fn->set_enq_deq_fn(queue,
						      pktout_enqueue,
						      pktout_enq_multi,
						      NULL,
						      NULL);

			entry->out_queue[i].queue = queue;
		}
	}

	if (entry->ops->output_queues_config)
		return entry->ops->output_queues_config(entry, param);

	return 0;
}

int odp_pktin_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (num < 0) {
		_ODP_DBG("Bad param: num %i\n", num);
		return -1;
	}

	mode = entry->param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_QUEUE &&
	    mode != ODP_PKTIN_MODE_SCHED)
		return -1;

	num_queues = entry->num_in_queue;

	if (queues) {
		if (num_queues < num)
			num = num_queues;

		for (i = 0; i < num; i++)
			queues[i] = entry->in_queue[i].queue;
	}

	return num_queues;
}

int odp_pktin_queue(odp_pktio_t pktio, odp_pktin_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktin_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (num < 0) {
		_ODP_DBG("Bad param: num %i\n", num);
		return -1;
	}

	mode = entry->param.in_mode;

	if (mode == ODP_PKTIN_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTIN_MODE_DIRECT)
		return -1;

	num_queues = entry->num_in_queue;

	if (queues) {
		if (num_queues < num)
			num = num_queues;

		for (i = 0; i < num; i++)
			queues[i] = entry->in_queue[i].pktin;
	}

	return num_queues;
}

int odp_pktout_event_queue(odp_pktio_t pktio, odp_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	mode = entry->param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_QUEUE)
		return -1;

	num_queues = entry->num_out_queue;

	if (queues && num > 0) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->out_queue[i].queue;
	}

	return num_queues;
}

int odp_pktout_queue(odp_pktio_t pktio, odp_pktout_queue_t queues[], int num)
{
	pktio_entry_t *entry;
	odp_pktout_mode_t mode;
	int i;
	int num_queues;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	mode = entry->param.out_mode;

	if (mode == ODP_PKTOUT_MODE_DISABLED)
		return 0;

	if (mode != ODP_PKTOUT_MODE_DIRECT)
		return -1;

	num_queues = entry->num_out_queue;

	if (queues && num > 0) {
		for (i = 0; i < num && i < num_queues; i++)
			queues[i] = entry->out_queue[i].pktout;
	}

	return num_queues;
}

int odp_pktin_recv(odp_pktin_queue_t queue, odp_packet_t packets[], int num)
{
	pktio_entry_t *entry;
	odp_pktio_t pktio = queue.pktio;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (odp_unlikely(entry->state != PKTIO_STATE_STARTED))
		return 0;

	ret = entry->ops->recv(entry, queue.index, packets, num);
	if (_ODP_PCAPNG)
		_odp_pcapng_dump_pkts(entry, queue.index, packets, ret);

	return ret;
}

int odp_pktin_recv_tmo(odp_pktin_queue_t queue, odp_packet_t packets[], int num,
		       uint64_t wait)
{
	int ret;
	odp_time_t t1, t2;
	struct timespec ts;
	int started = 0;
	uint64_t sleep_round = 0;
	pktio_entry_t *entry;

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000 * SLEEP_USEC;

	entry = get_pktio_entry(queue.pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)queue.pktio);
		return -1;
	}

	if (odp_unlikely(entry->state != PKTIO_STATE_STARTED))
		return 0;

	if (entry->ops->recv_tmo && wait != ODP_PKTIN_NO_WAIT) {
		ret = entry->ops->recv_tmo(entry, queue.index, packets, num,
					      wait);
		if (_ODP_PCAPNG)
			_odp_pcapng_dump_pkts(entry, queue.index, packets, ret);

		return ret;
	}

	while (1) {
		ret = entry->ops->recv(entry, queue.index, packets, num);
		if (_ODP_PCAPNG)
			_odp_pcapng_dump_pkts(entry, queue.index, packets, ret);

		if (ret != 0 || wait == 0)
			return ret;

		/* Avoid unnecessary system calls. Record the start time
		 * only when needed and after the first call to recv. */
		if (odp_unlikely(!started)) {
			odp_time_t t;

			/* Avoid overflow issues for large wait times */
			if (wait > MAX_WAIT_TIME)
				wait = MAX_WAIT_TIME;
			t = odp_time_local_from_ns(wait * 1000);
			started = 1;
			t1 = odp_time_sum(odp_time_local(), t);
		}

		/* Check every SLEEP_CHECK rounds if total wait time
		 * has been exceeded. */
		if ((++sleep_round & (SLEEP_CHECK - 1)) == 0) {
			t2 = odp_time_local();

			if (odp_time_cmp(t2, t1) > 0)
				return 0;
		}
		wait = wait > SLEEP_USEC ? wait - SLEEP_USEC : 0;

		nanosleep(&ts, NULL);
	}
}

int odp_pktin_recv_mq_tmo(const odp_pktin_queue_t queues[], uint32_t num_q, uint32_t *from,
			  odp_packet_t packets[], int num, uint64_t wait)
{
	uint32_t i;
	int ret;
	odp_time_t t1, t2;
	struct timespec ts;
	int started = 0;
	uint64_t sleep_round = 0;
	int trial_successful = 0;
	uint32_t lfrom = 0;

	for (i = 0; i < num_q; i++) {
		ret = odp_pktin_recv(queues[i], packets, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	if (wait == 0)
		return 0;

	ret = _odp_sock_recv_mq_tmo_try_int_driven(queues, num_q, &lfrom,
						   packets, num, wait,
						   &trial_successful);
	if (ret > 0 && from)
		*from = lfrom;
	if (trial_successful) {
		if (_ODP_PCAPNG) {
			pktio_entry_t *entry;

			entry = get_pktio_entry(queues[lfrom].pktio);
			if (entry)
				_odp_pcapng_dump_pkts(entry, lfrom, packets, ret);
		}

		return ret;
	}

	ts.tv_sec  = 0;
	ts.tv_nsec = 1000 * SLEEP_USEC;

	while (1) {
		for (i = 0; i < num_q; i++) {
			ret = odp_pktin_recv(queues[i], packets, num);

			if (ret > 0 && from)
				*from = i;

			if (ret != 0)
				return ret;
		}

		if (wait == 0)
			return 0;

		if (odp_unlikely(!started)) {
			odp_time_t t;

			/* Avoid overflow issues for large wait times */
			if (wait > MAX_WAIT_TIME)
				wait = MAX_WAIT_TIME;
			t = odp_time_local_from_ns(wait * 1000);
			started = 1;
			t1 = odp_time_sum(odp_time_local(), t);
		}

		/* Check every SLEEP_CHECK rounds if total wait time
		 * has been exceeded. */
		if ((++sleep_round & (SLEEP_CHECK - 1)) == 0) {
			t2 = odp_time_local();

			if (odp_time_cmp(t2, t1) > 0)
				return 0;
		}
		wait = wait > SLEEP_USEC ? wait - SLEEP_USEC : 0;

		nanosleep(&ts, NULL);
	}
}

uint64_t odp_pktin_wait_time(uint64_t nsec)
{
	if (nsec == 0)
		return 0;

	/* number of microseconds rounded up by one, so that
	 * recv_mq_tmo call waits at least 'nsec' nanoseconds. */
	return (nsec / (1000)) + 1;
}

static inline odp_bool_t check_tx_compl(const odp_packet_hdr_t *hdr, int pkt_idx,
					tx_compl_info_t *info, odp_pool_t pool,
					odp_atomic_u32_t *status_map, uint16_t *num)
{
	tx_compl_info_t *i;

	if (odp_likely(hdr->p.flags.tx_compl_ev == 0 && hdr->p.flags.tx_compl_poll == 0))
		return true;

	i = &info[*num];
	i->idx = pkt_idx;

	if (hdr->p.flags.tx_compl_ev) {
		i->buf = odp_buffer_alloc(pool);

		if (i->buf == ODP_BUFFER_INVALID)
			return false;

		i->user_ptr = hdr->user_ptr;
		i->queue = hdr->dst_queue;
		i->mode = ODP_PACKET_TX_COMPL_EVENT;
	} else {
		i->status = &status_map[hdr->tx_compl_id];
		odp_atomic_store_rel_u32(i->status, 0);
		i->mode = ODP_PACKET_TX_COMPL_POLL;
	}

	(*num)++;

	return true;
}

static inline int prepare_tx_compl(const odp_packet_t packets[], int num, tx_compl_info_t *info,
				   odp_pool_t pool, odp_atomic_u32_t *status_map,
				   uint16_t *num_tx_c)
{
	int num_to_send = num;

	for (int i = 0; i < num; i++)
		if (!check_tx_compl(packet_hdr(packets[i]), i, info, pool, status_map, num_tx_c)) {
			num_to_send = info[*num_tx_c].idx;
			break;
		}

	return num_to_send;
}

static inline void send_tx_compl_event(odp_buffer_t buf, const void *user_ptr, odp_queue_t queue)
{
	_odp_pktio_tx_compl_t *data;
	odp_event_t ev;

	data = odp_buffer_addr(buf);
	data->user_ptr = user_ptr;
	ev = odp_buffer_to_event(buf);
	_odp_event_type_set(ev, ODP_EVENT_PACKET_TX_COMPL);

	if (odp_unlikely(odp_queue_enq(queue, ev))) {
		_ODP_ERR("Failed to enqueue Tx completion event\n");
		odp_event_free(ev);
	}
}

static inline void finish_tx_compl(tx_compl_info_t *info, uint16_t num, int num_sent)
{
	tx_compl_info_t *i;

	for (int j = 0; j < num; j++) {
		i = &info[j];

		if (i->idx < num_sent) {
			if (i->mode == ODP_PACKET_TX_COMPL_EVENT)
				send_tx_compl_event(i->buf, i->user_ptr, i->queue);
			else
				odp_atomic_store_rel_u32(i->status, 1);
		} else if (i->mode == ODP_PACKET_TX_COMPL_EVENT) {
			odp_buffer_free(i->buf);
		}
	}
}

int odp_pktout_send(odp_pktout_queue_t queue, const odp_packet_t packets[],
		    int num)
{
	pktio_entry_t *entry;
	odp_pktio_t pktio = queue.pktio;
	tx_compl_info_t tx_compl_info[num];
	uint16_t num_tx_c = 0;
	int num_to_send = num, num_sent;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		_ODP_DBG("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)pktio);
		return -1;
	}

	if (odp_unlikely(entry->state != PKTIO_STATE_STARTED))
		return 0;

	if (_ODP_PCAPNG)
		_odp_pcapng_dump_pkts(entry, queue.index, packets, num);

	if (odp_unlikely(_odp_pktio_tx_compl_enabled(entry))) {
		odp_pool_t tx_compl_pool = entry->tx_compl_pool;
		odp_atomic_u32_t *tx_compl_status = entry->tx_compl_status;

		num_to_send = prepare_tx_compl(packets, num, tx_compl_info, tx_compl_pool,
					       tx_compl_status, &num_tx_c);
	}

	num_sent = entry->ops->send(entry, queue.index, packets, num_to_send);

	if (odp_unlikely(num_tx_c))
		finish_tx_compl(tx_compl_info, num_tx_c, num_sent);

	return num_sent;
}

/** Get printable format of odp_pktio_t */
uint64_t odp_pktio_to_u64(odp_pktio_t hdl)
{
	return _odp_pri(hdl);
}

int odp_pktout_ts_read(odp_pktio_t hdl, odp_time_t *ts)
{
	pktio_entry_t *entry;
	uint64_t ts_val;

	entry = get_pktio_entry(hdl);
	if (odp_unlikely(entry == NULL)) {
		_ODP_ERR("pktio entry %" PRIuPTR " does not exist\n", (uintptr_t)hdl);
		return -1;
	}

	if (odp_atomic_load_u64(&entry->tx_ts) == 0)
		return 1;

	ts_val = odp_atomic_xchg_u64(&entry->tx_ts, 0);
	if (odp_unlikely(ts_val == 0))
		return 1;

	ts->u64 = ts_val;
	return 0;
}

void odp_lso_profile_param_init(odp_lso_profile_param_t *param)
{
	memset(param, 0, sizeof(odp_lso_profile_param_t));

	param->lso_proto = ODP_LSO_PROTO_NONE;
}

odp_lso_profile_t odp_lso_profile_create(odp_pktio_t pktio, const odp_lso_profile_param_t *param)
{
	uint32_t i, num_custom, mod_op, offset, size;
	lso_profile_t *lso_prof = NULL;
	(void)pktio;

	/* Currently only IPv4 and custom implemented */
	if (param->lso_proto != ODP_LSO_PROTO_IPV4 &&
	    param->lso_proto != ODP_LSO_PROTO_CUSTOM) {
		_ODP_ERR("Protocol not supported\n");
		return ODP_LSO_PROFILE_INVALID;
	}

	if (param->lso_proto == ODP_LSO_PROTO_CUSTOM) {
		num_custom = param->custom.num_custom;
		if (num_custom > ODP_LSO_MAX_CUSTOM) {
			_ODP_ERR("Too many custom fields\n");
			return ODP_LSO_PROFILE_INVALID;
		}

		for (i = 0; i < num_custom; i++) {
			mod_op = param->custom.field[i].mod_op;
			offset = param->custom.field[i].offset;
			size   = param->custom.field[i].size;

			if (offset > PKTIO_LSO_MAX_PAYLOAD_OFFSET) {
				_ODP_ERR("Too large custom field offset %u\n", offset);
				return ODP_LSO_PROFILE_INVALID;
			}

			/* Currently only segment number supported */
			if (mod_op != ODP_LSO_ADD_SEGMENT_NUM) {
				_ODP_ERR("Custom modify operation %u not supported\n", mod_op);
				return ODP_LSO_PROFILE_INVALID;
			}

			if (size != 1 && size != 2 && size != 4 && size != 8) {
				_ODP_ERR("Bad custom field size %u\n", size);
				return ODP_LSO_PROFILE_INVALID;
			}
		}
	}

	odp_spinlock_lock(&pktio_global->lock);

	if (pktio_global->num_lso_profiles >= PKTIO_LSO_PROFILES) {
		odp_spinlock_unlock(&pktio_global->lock);
		_ODP_ERR("All LSO profiles used already: %u\n", PKTIO_LSO_PROFILES);
		return ODP_LSO_PROFILE_INVALID;
	}

	for (i = 0; i < PKTIO_LSO_PROFILES; i++) {
		if (pktio_global->lso_profile[i].used == 0) {
			lso_prof = &pktio_global->lso_profile[i];
			lso_prof->used = 1;
			pktio_global->num_lso_profiles++;
			break;
		}
	}

	odp_spinlock_unlock(&pktio_global->lock);

	if (lso_prof == NULL) {
		_ODP_ERR("Did not find free LSO profile\n");
		return ODP_LSO_PROFILE_INVALID;
	}

	lso_prof->param = *param;
	lso_prof->index = i;

	return (odp_lso_profile_t)(uintptr_t)lso_prof;
}

odp_lso_profile_t _odp_lso_prof_from_idx(uint8_t idx)
{
	return (odp_lso_profile_t)(uintptr_t)&pktio_global->lso_profile[idx];
}

static inline lso_profile_t *lso_profile_ptr(odp_lso_profile_t handle)
{
	return (lso_profile_t *)(uintptr_t)handle;
}

int odp_lso_profile_destroy(odp_lso_profile_t lso_profile)
{
	lso_profile_t *lso_prof = lso_profile_ptr(lso_profile);

	if (lso_profile == ODP_LSO_PROFILE_INVALID || lso_prof->used == 0) {
		_ODP_ERR("Bad handle\n");
		return -1;
	}

	odp_spinlock_lock(&pktio_global->lock);
	lso_prof->used = 0;
	pktio_global->num_lso_profiles--;
	odp_spinlock_unlock(&pktio_global->lock);

	return 0;
}

int odp_packet_lso_request(odp_packet_t pkt, const odp_packet_lso_opt_t *lso_opt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	lso_profile_t *lso_prof = lso_profile_ptr(lso_opt->lso_profile);
	uint32_t payload_offset = lso_opt->payload_offset;

	if (odp_unlikely(lso_opt->lso_profile == ODP_LSO_PROFILE_INVALID || lso_prof->used == 0)) {
		_ODP_ERR("Bad LSO profile handle\n");
		return -1;
	}

	if (odp_unlikely(payload_offset > PKTIO_LSO_MAX_PAYLOAD_OFFSET)) {
		_ODP_ERR("Too large LSO payload offset\n");
		return -1;
	}

	if (odp_unlikely(payload_offset > packet_len(pkt_hdr))) {
		_ODP_ERR("LSO payload offset larger than packet data length\n");
		return -1;
	}

	if (odp_packet_payload_offset_set(pkt, payload_offset)) {
		_ODP_ERR("Payload offset set failed\n");
		return -1;
	}

	pkt_hdr->p.flags.lso     = 1;
	pkt_hdr->lso_max_payload = lso_opt->max_payload_len;
	pkt_hdr->lso_profile_idx = lso_prof->index;

	return 0;
}

static int lso_update_ipv4(odp_packet_t pkt, int index, int num_pkt,
			   uint32_t l3_offset, uint32_t payload_len)
{
	_odp_ipv4hdr_t *ipv4;
	uint32_t pkt_len = odp_packet_len(pkt);
	uint16_t tot_len = pkt_len - l3_offset;
	int ret = 0;
	uint16_t frag_offset;

	odp_packet_l3_offset_set(pkt, l3_offset);
	ipv4 = odp_packet_l3_ptr(pkt, NULL);
	ipv4->tot_len = odp_cpu_to_be_16(tot_len);

	/* IP payload offset in 8 byte blocks */
	frag_offset = ((uint32_t)index * payload_len) / 8;

	/* More fragments flag */
	if (index < (num_pkt - 1))
		frag_offset |= _ODP_IPV4HDR_FRAG_OFFSET_MORE_FRAGS;

	ipv4->frag_offset = odp_cpu_to_be_16(frag_offset);
	ret = _odp_packet_ipv4_chksum_insert(pkt);

	return ret;
}

static int lso_update_custom(lso_profile_t *lso_prof, odp_packet_t pkt, int segnum)
{
	void *ptr;
	int i, mod_op;
	uint32_t offset;
	uint8_t size;
	int num_custom = lso_prof->param.custom.num_custom;
	uint64_t u64 = 0;
	uint32_t u32 = 0;
	uint16_t u16 = 0;
	uint8_t  u8 = 0;

	for (i = 0; i < num_custom; i++) {
		mod_op = lso_prof->param.custom.field[i].mod_op;
		offset = lso_prof->param.custom.field[i].offset;
		size   = lso_prof->param.custom.field[i].size;

		if (size == 8)
			ptr = &u64;
		else if (size == 4)
			ptr = &u32;
		else if (size == 2)
			ptr = &u16;
		else
			ptr = &u8;

		if (odp_packet_copy_to_mem(pkt, offset, size, ptr)) {
			_ODP_ERR("Read from packet failed at offset %u\n", offset);
			return -1;
		}

		if (mod_op == ODP_LSO_ADD_SEGMENT_NUM) {
			if (size == 8)
				u64 = odp_cpu_to_be_64(segnum + odp_be_to_cpu_64(u64));
			else if (size == 4)
				u32 = odp_cpu_to_be_32(segnum + odp_be_to_cpu_32(u32));
			else if (size == 2)
				u16 = odp_cpu_to_be_16(segnum + odp_be_to_cpu_16(u16));
			else
				u8 += segnum;
		}

		if (odp_packet_copy_from_mem(pkt, offset, size, ptr)) {
			_ODP_ERR("Write to packet failed at offset %u\n", offset);
			return -1;
		}
	}

	return 0;
}

int _odp_lso_num_packets(odp_packet_t packet, const odp_packet_lso_opt_t *lso_opt,
			 uint32_t *len_out, uint32_t *left_over_out)
{
	uint32_t num_pkt, left_over, l3_offset, iphdr_len;
	odp_lso_profile_t lso_profile = lso_opt->lso_profile;
	lso_profile_t *lso_prof = lso_profile_ptr(lso_profile);
	uint32_t payload_len = lso_opt->max_payload_len;
	uint32_t hdr_len     = lso_opt->payload_offset;
	uint32_t pkt_len     = odp_packet_len(packet);
	uint32_t pkt_payload = pkt_len - hdr_len;

	if (odp_unlikely(hdr_len > PKTIO_LSO_MAX_PAYLOAD_OFFSET)) {
		_ODP_ERR("Too large LSO payload offset\n");
		return -1;
	}

	if (odp_unlikely(hdr_len > pkt_len)) {
		_ODP_ERR("LSO payload offset larger than packet data length\n");
		return -1;
	}

	if (odp_unlikely(hdr_len + payload_len > odp_packet_len(packet))) {
		/* Packet does not need segmentation */
		*len_out       = payload_len;
		*left_over_out = 0;

		return 1;
	}

	if (lso_prof->param.lso_proto == ODP_LSO_PROTO_IPV4) {
		l3_offset = odp_packet_l3_offset(packet);
		iphdr_len = hdr_len - l3_offset;

		if (l3_offset == ODP_PACKET_OFFSET_INVALID) {
			_ODP_ERR("Invalid L3 offset\n");
			return -1;
		}

		if (hdr_len < l3_offset || iphdr_len < _ODP_IPV4HDR_LEN) {
			_ODP_ERR("Bad payload or L3 offset\n");
			return -1;
		}

		/* Round down payload len to a multiple of 8 (on other than the last fragment). */
		payload_len = (payload_len / 8) * 8;
	}

	num_pkt = pkt_payload / payload_len;

	left_over = pkt_payload - (num_pkt * payload_len);
	if (left_over)
		num_pkt++;

	if (num_pkt > PKTIO_LSO_MAX_SEGMENTS) {
		_ODP_ERR("Too many LSO segments %i. Maximum is %i\n", num_pkt,
			 PKTIO_LSO_MAX_SEGMENTS);
		return -1;
	}

	*len_out       = payload_len;
	*left_over_out = left_over;

	return num_pkt;
}

int _odp_lso_create_packets(odp_packet_t packet, const odp_packet_lso_opt_t *lso_opt,
			    uint32_t payload_len, uint32_t left_over_len,
			    odp_packet_t pkt_out[], int num_pkt)
{
	int i, num;
	uint32_t offset;
	odp_packet_t pkt;
	odp_lso_profile_t lso_profile = lso_opt->lso_profile;
	lso_profile_t *lso_prof = lso_profile_ptr(lso_profile);
	const uint32_t hdr_len = lso_opt->payload_offset;
	const uint32_t pkt_len = hdr_len + payload_len;
	odp_pool_t pool = odp_packet_pool(packet);
	int num_free = 0;
	int num_full = num_pkt;

	if (left_over_len)
		num_full = num_pkt - 1;

	num = odp_packet_alloc_multi(pool, pkt_len, pkt_out, num_full);
	if (odp_unlikely(num < num_full)) {
		_ODP_DBG("Alloc failed %i\n", num);
		if (num > 0) {
			num_free = num;
			goto error;
		}
	}

	if (left_over_len) {
		pkt = odp_packet_alloc(pool, hdr_len + left_over_len);
		if (pkt == ODP_PACKET_INVALID) {
			_ODP_DBG("Alloc failed\n");
			num_free = num_full;
			goto error;
		}

		pkt_out[num_pkt - 1] = pkt;
	}

	num_free = num_pkt;

	/* Copy headers */
	for (i = 0; i < num_pkt; i++) {
		if (odp_packet_copy_from_pkt(pkt_out[i], 0, packet, 0, hdr_len)) {
			_ODP_ERR("Header copy failed\n");
			goto error;
		}
	}

	/* Copy payload */
	for (i = 0; i < num_full; i++) {
		offset = hdr_len + (i * payload_len);
		if (odp_packet_copy_from_pkt(pkt_out[i], hdr_len, packet, offset, payload_len)) {
			_ODP_ERR("Payload copy failed\n");
			goto error;
		}
	}

	/* Copy left over payload */
	if (left_over_len) {
		offset = hdr_len + (num_full * payload_len);
		if (odp_packet_copy_from_pkt(pkt_out[num_pkt - 1], hdr_len, packet, offset,
					     left_over_len)){
			_ODP_ERR("Payload copy failed\n");
			goto error;
		}
	}

	if (lso_prof->param.lso_proto == ODP_LSO_PROTO_IPV4) {
		offset = odp_packet_l3_offset(packet);

		if (offset == ODP_PACKET_OFFSET_INVALID) {
			_ODP_ERR("Invalid L3 offset\n");
			goto error;
		}

		for (i = 0; i < num_pkt; i++) {
			if (lso_update_ipv4(pkt_out[i], i, num_pkt, offset, payload_len)) {
				_ODP_ERR("IPv4 header update failed. Packet %i.\n", i);
				goto error;
			}
		}
	} else {
		/* Update custom fields */
		int num_custom = lso_prof->param.custom.num_custom;

		for (i = 0; num_custom && i < num_pkt; i++) {
			if (lso_update_custom(lso_prof, pkt_out[i], i)) {
				_ODP_ERR("Custom field update failed. Segment %i\n", i);
				goto error;
			}
		}
	}

	return 0;

error:
	odp_packet_free_multi(pkt_out, num_free);
	return -1;
}

static int pktout_send_lso(odp_pktout_queue_t queue, odp_packet_t packet,
			   const odp_packet_lso_opt_t *lso_opt)
{
	int ret, num_pkt;
	uint32_t payload_len, left_over_len;

	/* Calculate number of packets */
	num_pkt = _odp_lso_num_packets(packet, lso_opt, &payload_len, &left_over_len);
	if (odp_unlikely(num_pkt <= 0))
		return -1;

	if (odp_unlikely(num_pkt == 1)) {
		/* Segmentation not needed */
		if (odp_pktout_send(queue, &packet, 1) != 1)
			return -1;

		return 0;
	}

	/* Create packets */
	odp_packet_t pkt_out[num_pkt];

	ret = _odp_lso_create_packets(packet, lso_opt, payload_len, left_over_len, pkt_out,
				      num_pkt);

	if (odp_unlikely(ret))
		return -1;

	/* Send LSO packets */
	ret = odp_pktout_send(queue, pkt_out, num_pkt);

	if (ret < num_pkt) {
		int first_free = 0;
		int num_free = num_pkt;

		_ODP_DBG("Packet send failed %i\n", ret);

		if (ret > 0) {
			first_free = ret;
			num_free = num_pkt - ret;
		}

		odp_packet_free_multi(&pkt_out[first_free], num_free);
		return -1;
	}

	/* Free original packet */
	odp_packet_free(packet);

	return 0;
}

int odp_pktout_send_lso(odp_pktout_queue_t queue, const odp_packet_t packet[], int num,
			const odp_packet_lso_opt_t *opt)
{
	int i;
	odp_packet_t pkt;
	odp_packet_lso_opt_t lso_opt;
	const odp_packet_lso_opt_t *opt_ptr = &lso_opt;

	if (odp_unlikely(num <= 0)) {
		_ODP_ERR("No packets\n");
		return -1;
	}

	memset(&lso_opt, 0, sizeof(odp_packet_lso_opt_t));
	if (opt)
		opt_ptr = opt;

	for (i = 0; i < num; i++) {
		pkt = packet[i];

		if (opt == NULL) {
			odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

			if (pkt_hdr->p.flags.lso == 0) {
				_ODP_ERR("No LSO options on packet %i\n", i);
				if (i == 0)
					return -1;

				return i;
			}

			lso_opt.lso_profile     = _odp_lso_prof_from_idx(pkt_hdr->lso_profile_idx);
			lso_opt.payload_offset  = odp_packet_payload_offset(pkt);
			lso_opt.max_payload_len = pkt_hdr->lso_max_payload;
		}

		if (odp_unlikely(pktout_send_lso(queue, pkt, opt_ptr))) {
			_ODP_DBG("LSO output failed on packet %i\n", i);
			return i;
		}
	}

	return i;
}

void _odp_pktio_process_tx_compl(const pktio_entry_t *entry, const odp_packet_t packets[], int num)
{
	odp_packet_hdr_t *hdr;
	odp_pool_t pool = entry->tx_compl_pool;
	odp_buffer_t buf;
	odp_atomic_u32_t *status_map = entry->tx_compl_status;

	for (int i = 0; i < num; i++) {
		hdr = packet_hdr(packets[i]);

		if (odp_likely(hdr->p.flags.tx_compl_ev == 0 && hdr->p.flags.tx_compl_poll == 0))
			continue;

		if (hdr->p.flags.tx_compl_ev) {
			buf = odp_buffer_alloc(pool);

			if (odp_unlikely(buf == ODP_BUFFER_INVALID))
				continue;

			send_tx_compl_event(buf, hdr->user_ptr, hdr->dst_queue);
		} else {
			odp_atomic_store_rel_u32(&status_map[hdr->tx_compl_id], 1);
		}
	}
}

void
odp_proto_stats_param_init(odp_proto_stats_param_t *param)
{
	if (param)
		memset(param, 0, sizeof(*param));
}

int
odp_proto_stats_capability(odp_pktio_t pktio, odp_proto_stats_capability_t *capa)
{
	(void)pktio;

	if (capa == NULL)
		return -1;

	memset(capa, 0, sizeof(*capa));

	return 0;
}

odp_proto_stats_t
odp_proto_stats_lookup(const char *name)
{
	(void)name;

	return ODP_PROTO_STATS_INVALID;
}

odp_proto_stats_t
odp_proto_stats_create(const char *name, const odp_proto_stats_param_t *param)
{
	(void)name;
	(void)param;

	return ODP_PROTO_STATS_INVALID;
}

int
odp_proto_stats_destroy(odp_proto_stats_t stat)
{
	(void)stat;

	return 0;
}

int
odp_proto_stats(odp_proto_stats_t stat, odp_proto_stats_data_t *data)
{
	(void)stat;

	memset(data, 0, sizeof(odp_proto_stats_data_t));

	return 0;
}

void
odp_proto_stats_print(odp_proto_stats_t stat)
{
	(void)stat;
}
