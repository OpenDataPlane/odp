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
	ODP_ERR("NOT Supported yet! Enumerator API %s Registration!\n.",
		param->api_name);

	return ODPDRV_ENUMR_INVALID;
}

odpdrv_device_t odpdrv_device_create(odpdrv_device_param_t *param)
{
	ODP_ERR("odpdrv_device_create not Supported yet! devaddress: %s\n.",
		param->address);
	return ODPDRV_DEVICE_INVALID;
}

void odpdrv_device_destroy(odpdrv_device_t dev)
{
	if (dev == ODPDRV_DEVICE_INVALID)
		ODP_ERR("Invalid device\n");
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
}

int odpdrv_print_all(void)
{
	_odpdrv_enumr_class_t *enumr_c;

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

	if (init_global_status == UNDONE)
		return 0;

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
