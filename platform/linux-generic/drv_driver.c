/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>

#include <odp_config_internal.h>
#include <_ishmpool_internal.h>

#include <odp/api/std_types.h>
#include <odp/api/debug.h>
#include <odp/api/rwlock_recursive.h>
#include <odp/drv/driver.h>
#include <odp/drv/spec/driver.h>
#include <odp_debug_internal.h>
#include <drv_driver_internal.h>

static enum {UNDONE, IN_PROGRESS, DONE} init_global_status;

/* pool from which different list elements are alocated: */
#define ELT_POOL_SIZE (1 << 20)  /* 1Mb */
static _odp_ishm_pool_t *list_elt_pool;

typedef struct _odpdrv_enumr_class_s _odpdrv_enumr_class_t;
typedef struct _odpdrv_enumr_s _odpdrv_enumr_t;

/* an enumerator class (list element) */
struct _odpdrv_enumr_class_s {
	odpdrv_enumr_class_param_t param;
	int probed;
	_odp_ishm_pool_t *pool;
	struct _odpdrv_enumr_class_s *next;
};

/* the enumerator class list: */
typedef struct _odpdrv_enumr_class_lst_t {
	odp_rwlock_recursive_t lock;
	_odpdrv_enumr_class_t *head;
} _odpdrv_enumr_class_lst_t;
static struct _odpdrv_enumr_class_lst_t enumr_class_lst;

/* an enumerator (list element) */
struct _odpdrv_enumr_s {
	odpdrv_enumr_param_t param;
	int probed;
	struct _odpdrv_enumr_s *next;
};

/* the enumerator list: */
typedef struct _odpdrv_enumr_lst_t {
	odp_rwlock_recursive_t lock;
	_odpdrv_enumr_t *head;
} _odpdrv_enumr_lst_t;
static struct _odpdrv_enumr_lst_t enumr_lst;

/* some driver elements (such as enumeraor classes, drivers, devio) may
 * register before init_global and init_local complete. Mutex will fail
 * in this cases but should be used later on.
 * These functions disable the usage of Mutex while it is global init i.e.
 * while single threaded*/
static void enumr_class_list_read_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_lock(&enumr_class_lst.lock);
}

static void enumr_class_list_read_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_unlock(&enumr_class_lst.lock);
}

static void enumr_class_list_write_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_lock(&enumr_class_lst.lock);
}

static void enumr_class_list_write_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_unlock(&enumr_class_lst.lock);
}

static void enumr_list_read_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_lock(&enumr_lst.lock);
}

static void enumr_list_read_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_unlock(&enumr_lst.lock);
}

static void enumr_list_write_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_lock(&enumr_lst.lock);
}

static void enumr_list_write_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_unlock(&enumr_lst.lock);
}

/* some functions to get internal pointers from handles... */
static inline _odpdrv_enumr_class_t *get_enumr_class(odpdrv_enumr_class_t class)
{
	return (_odpdrv_enumr_class_t *)(void *)class;
}

odpdrv_enumr_class_t odpdrv_enumr_class_register(odpdrv_enumr_class_param_t
						 *param)
{
	_odpdrv_enumr_class_t *enumr_c;

	/* parse the list of already registered enumerator class to make
	 * sure no enumerator with identical name already exists:
	 */
	enumr_class_list_write_lock();
	enumr_c = enumr_class_lst.head;
	while (enumr_c) {
		if (strncmp(param->name, enumr_c->param.name,
			    ODPDRV_NAME_SIZE) == 0) {
			ODP_ERR("enumerator class %s already exists!\n",
				param->name);
			enumr_class_list_write_unlock();
			return ODPDRV_ENUMR_CLASS_INVALID;
		}
		enumr_c = enumr_c->next;
	}

	/* allocate memory for the new enumerator class:
	 * If init_global has not been done yet, then, we cannot allocate
	 * from any _ishm pool (ishm has not even been initialised at this
	 * stage...this happens when statically linked enumerator classes
	 * register: their __constructor__ function is run before main()
	 * is called). But any malloc performed here(before init_global)
	 * will be inherited by any odpthreads (process or pthreads) as we
	 * are still running in the ODP instantiation processes and all
	 * other processes are guaranteed to be descendent of this one...
	 * If init_global has been done, then we allocate from the _ishm pool
	 * to guarantee visibility from any ODP thread.
	 */

	if (init_global_status == UNDONE) {
		enumr_c = malloc(sizeof(_odpdrv_enumr_class_t));
		if (!enumr_c) {
			enumr_class_list_write_unlock();
			return ODPDRV_ENUMR_CLASS_INVALID;
		}
		enumr_c->pool = NULL;
	} else {
		enumr_c = _odp_ishm_pool_alloc(list_elt_pool,
					       sizeof(_odpdrv_enumr_class_t));
		if (!enumr_c) {
			ODP_ERR("_odp_ishm_pool_alloc failed!\n");
			enumr_class_list_write_unlock();
			return ODPDRV_ENUMR_CLASS_INVALID;
		}
		enumr_c->pool = list_elt_pool;
	}

	/* save init parameters and insert enumerator class in list */
	enumr_c->param = *param;
	enumr_c->probed = 0;
	enumr_c->next = enumr_class_lst.head;
	enumr_class_lst.head = enumr_c;
	enumr_class_list_write_unlock();

	return (odpdrv_enumr_class_t)enumr_c;
}

odpdrv_enumr_t odpdrv_enumr_register(odpdrv_enumr_param_t *param)
{
	_odpdrv_enumr_t *enumr;
	_odpdrv_enumr_class_t *enumr_c;
	int found_class = 0;

	/* If init_global has not been done yet, we have a big issue,
	 * as none of the enumerator classes have been probed before that!
	 * We cannot even issue an error as ODP_* functions have not been
	 * initialised yet, but this is no good...
	 */
	if (init_global_status == UNDONE)
		return ODPDRV_ENUMR_INVALID;

	/* make sure that the provided enumerator_class does indeed exist: */
	enumr_class_list_read_lock();
	enumr_c = enumr_class_lst.head;
	while (enumr_c) {
		if (get_enumr_class(param->enumr_class) == enumr_c) {
			found_class = 1;
			break;
		}
		enumr_c = enumr_c->next;
	}
	enumr_class_list_read_unlock();
	if (!found_class) {
		ODP_ERR("invalid enumerator class provided!\n");
		return ODPDRV_ENUMR_INVALID;
	}

	/* allocate memory for the new enumerator */
	enumr = _odp_ishm_pool_alloc(list_elt_pool,
				     sizeof(_odpdrv_enumr_t));
	if (!enumr) {
		ODP_ERR("_odp_ishm_pool_alloc failed!\n");
		return ODPDRV_ENUMR_INVALID;
	}

	/* save init parameters and insert enumerator in list */
	enumr->param = *param;
	enumr->probed = 0;
	enumr_list_write_lock();
	enumr->next = enumr_lst.head;
	enumr_lst.head = enumr;
	enumr_list_write_unlock();

	return (odpdrv_enumr_t)enumr;
}

odpdrv_device_t odpdrv_device_create(odpdrv_device_param_t *param)
{
	ODP_ERR("odpdrv_device_create not Supported yet! devaddress: %s\n.",
		param->address);
	return ODPDRV_DEVICE_INVALID;
}

int odpdrv_device_destroy(odpdrv_device_t dev,
			  void (*callback)(void *enum_dev), uint32_t flags)
{
	if (dev == ODPDRV_DEVICE_INVALID)
		ODP_ERR("Invalid device\n");
	if (callback != NULL)
		ODP_ERR("Callback not supported yet\n");
	if (flags != 0)
		ODP_ERR("flags not supported yet\n");

	return 0;
}

odpdrv_devio_t odpdrv_devio_register(odpdrv_devio_param_t *param)
{
	ODP_ERR("NOT Supported yet! Driver %s Registration!\n.",
		param->api_name);

	return ODPDRV_DEVIO_INVALID;
}

odpdrv_driver_t odpdrv_driver_register(odpdrv_driver_param_t *param)
{
	ODP_ERR("NOT Supported yet! Driver %s Registration!\n.",
		param->name);

	return ODPDRV_DRIVER_INVALID;
}

/* the following function is called each time probing is needed, i.e.
 * at init or after loading a new module as a module can be anything,
 * including enumerators or drivers */
void _odpdrv_driver_probe_drv_items(void)
{
	_odpdrv_enumr_class_t *enumr_c;
	_odpdrv_enumr_t *enumr;

	/* probe unprobed enumerators: */
	enumr_class_list_write_lock();
	enumr_c = enumr_class_lst.head;
	while (enumr_c) {
		if (!enumr_c->probed) {
			enumr_c->param.probe();
			enumr_c->probed = 1;
		}
		enumr_c = enumr_c->next;
	}
	enumr_class_list_write_unlock();

	/* go through the list of registered enumerator probing the new
	 * (never probed) ones:
	 */
	enumr_list_write_lock();
	enumr = enumr_lst.head;
	while (enumr) {
		if (!enumr->probed) {
			enumr->param.probe();
			enumr->probed = 1;
		}
		enumr = enumr->next;
	}
	enumr_list_write_unlock();
}

int odpdrv_print_all(void)
{
	_odpdrv_enumr_class_t *enumr_c;
	_odpdrv_enumr_t *enumr;

	/* we cannot use ODP_DBG before ODP init... */
	if (init_global_status == UNDONE)
		return 0;

	ODP_DBG("ODP Driver status:\n");

	/* print the list of registered enumerator classes: */
	enumr_class_list_read_lock();
	enumr_c = enumr_class_lst.head;
	ODP_DBG("The following enumerator classes have been registered:\n");
	while (enumr_c) {
		ODP_DBG(" class: %s\n", enumr_c->param.name);
		enumr_c = enumr_c->next;
	}
	enumr_class_list_read_unlock();

	/* print the list of registered enumerators: */
	enumr_list_read_lock();
	enumr = enumr_lst.head;
	ODP_DBG("The following enumerators have been registered:\n");
	while (enumr) {
		enumr_c = get_enumr_class(enumr->param.enumr_class);
		ODP_DBG(" enumerator: class: %s,"
			" API: %s, Version: %" PRIu32 "\n",
			enumr_c->param.name,
			enumr->param.api_name,
			enumr->param.api_version);
		enumr = enumr->next;
	}
	enumr_list_read_unlock();

	return 0;
}

int _odpdrv_driver_init_global(void)
{
	/* create a memory pool to for list elements: */
	list_elt_pool = _odp_ishm_pool_create(NULL, ELT_POOL_SIZE,
					      0, ELT_POOL_SIZE, 0);

	/* remember that init global is being done so the further list allocs
	 * are made from the list_elt_pool: */
	init_global_status = IN_PROGRESS;

	/* from now, we want to ensure mutex on the list: init lock: */
	odp_rwlock_recursive_init(&enumr_class_lst.lock);
	odp_rwlock_recursive_init(&enumr_lst.lock);

	/* probe things... */
	_odpdrv_driver_probe_drv_items();

	return 0;
}

int _odpdrv_driver_init_local(void)
{
	/* remember that init global is done, so list mutexes are used from
	 * now */
	init_global_status = DONE;
	return 0;
}

int _odpdrv_driver_term_global(void)
{
	_odpdrv_enumr_class_t *enumr_c;
	_odpdrv_enumr_t *enumr;

	if (init_global_status == UNDONE)
		return 0;

	/* remove all enumerators which are registered: */
	enumr_list_write_lock();
	while (enumr_lst.head) {
		enumr = enumr_lst.head;
		if (enumr->param.remove) { /* run remove callback, if any */
			if (enumr->param.remove())
				ODP_ERR("Enumerator (API %s) removal failed.\n",
					enumr->param.api_name);
		}
		enumr_lst.head = enumr->next;
		_odp_ishm_pool_free(list_elt_pool, enumr);
	}
	enumr_list_write_unlock();

	/* remove all enumerator classes which are registered: */
	enumr_class_list_write_lock();
	while (enumr_class_lst.head) {
		enumr_c = enumr_class_lst.head;
		if (enumr_c->param.remove) { /* run remove callback, if any */
			if (enumr_c->param.remove())
				ODP_ERR("Enumerator class %s removal failed.\n",
					enumr_c->param.name);
		}
		enumr_class_lst.head = enumr_c->next;
		if (enumr_c->pool)
			_odp_ishm_pool_free(list_elt_pool, enumr_c);
		else
			free(enumr_c);
	}
	enumr_class_list_write_unlock();

	/* destroy the list element pool: */
	_odp_ishm_pool_destroy(list_elt_pool);

	return 0;
}
