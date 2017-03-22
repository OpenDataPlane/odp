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
#include <odp/api/ticketlock.h>
#include <odp/drv/driver.h>
#include <odp/drv/spec/driver.h>
#include <odp_debug_internal.h>
#include <drv_driver_internal.h>

static enum {UNDONE, IN_PROGRESS, DONE} init_global_status;

static void device_destroy_terminate(odpdrv_device_t device);

/* pool from which different list elements are alocated: */
#define ELT_POOL_SIZE (1 << 20)  /* 1Mb */
static _odp_ishm_pool_t *list_elt_pool;

typedef struct _odpdrv_enumr_class_s _odpdrv_enumr_class_t;
typedef struct _odpdrv_enumr_s _odpdrv_enumr_t;
typedef struct _odpdrv_device_s _odpdrv_device_t;
typedef struct _odpdrv_devio_s _odpdrv_devio_t;
typedef struct _odpdrv_driver_s _odpdrv_driver_t;

static int unbind_device_driver(_odpdrv_device_t *dev,
				void (*callback)(odpdrv_device_t odpdrv_dev),
				uint32_t flags);

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

/* a device (list element) */
struct _odpdrv_device_s {
	odpdrv_device_param_t param;
	_odpdrv_driver_t *driver; /* driver for the device (if bound), or NULL*/
	_odpdrv_devio_t *devio;   /* devio used for device (if bound), or NULL*/
	void *driver_data;        /* anything that the driver need to attach. */
	void (*enumr_destroy_callback)(void *enum_dev);/*dev destroy callback */
	struct _odpdrv_device_s *next;
} _odpdrv_device_s;

/* the device list (all devices, from all enumerators): */
typedef struct _odpdrv_device_lst_t {
	odp_rwlock_recursive_t lock;
	_odpdrv_device_t *head;
} _odpdrv_device_lst_t;
static struct _odpdrv_device_lst_t device_lst;

/* a devio (list element) */
struct _odpdrv_devio_s {
	odpdrv_devio_param_t param;
	_odp_ishm_pool_t *pool;
	struct _odpdrv_devio_s *next;
} _odpdrv_devio_s;

/* the devio list: */
typedef struct _odpdrv_devio_lst_t {
	odp_rwlock_recursive_t lock;
	_odpdrv_devio_t *head;
} _odpdrv_devio_lst_t;
static struct _odpdrv_devio_lst_t devio_lst;

/* a driver (list element) */
struct _odpdrv_driver_s {
	odpdrv_driver_param_t param;
	_odp_ishm_pool_t *pool;
	odp_ticketlock_t probelock; /* to avoid concurrent probe on same drv*/
	struct _odpdrv_driver_s *next;
};

/* the driver list: */
typedef struct _odpdrv_driver_lst_t {
	odp_rwlock_recursive_t lock;
	_odpdrv_driver_t *head;
} _odpdrv_driver_lst_t;
static struct _odpdrv_driver_lst_t driver_lst;

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

static void dev_list_read_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_lock(&device_lst.lock);
}

static void dev_list_read_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_unlock(&device_lst.lock);
}

static void dev_list_write_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_lock(&device_lst.lock);
}

static void dev_list_write_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_unlock(&device_lst.lock);
}

static void devio_list_read_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_lock(&devio_lst.lock);
}

static void devio_list_read_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_unlock(&devio_lst.lock);
}

static void devio_list_write_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_lock(&devio_lst.lock);
}

static void devio_list_write_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_unlock(&devio_lst.lock);
}

static void driver_list_read_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_lock(&driver_lst.lock);
}

static void driver_list_read_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_read_unlock(&driver_lst.lock);
}

static void driver_list_write_lock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_lock(&driver_lst.lock);
}

static void driver_list_write_unlock(void)
{
	if (init_global_status == DONE)
		odp_rwlock_recursive_write_unlock(&driver_lst.lock);
}

/* some functions to get internal pointers from handles... */
static inline _odpdrv_enumr_class_t *get_enumr_class(odpdrv_enumr_class_t class)
{
	return (_odpdrv_enumr_class_t *)(void *)class;
}

static inline _odpdrv_enumr_t *get_enumr(odpdrv_enumr_t enumr)
{
	return (_odpdrv_enumr_t *)(void *)enumr;
}

static inline _odpdrv_device_t *get_device(odpdrv_device_t dev)
{
	return (_odpdrv_device_t *)(void *)dev;
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
	_odpdrv_device_t *dev;

	/* If init_global has not been done yet, we have a big issue. */
	if (init_global_status == UNDONE)
		return ODPDRV_DEVICE_INVALID;

	/* make sure that the provided device address does not already exist: */
	dev_list_read_lock();
	dev = device_lst.head;
	while (dev) {
		if (strcmp(param->address, dev->param.address) == 0) {
			ODP_ERR("device already exists!\n");
			dev_list_read_unlock();
			return ODPDRV_DEVICE_INVALID;
		}
		dev = dev->next;
	}
	dev_list_read_unlock();

	dev = _odp_ishm_pool_alloc(list_elt_pool,
				   sizeof(_odpdrv_device_t));
	if (!dev) {
		ODP_ERR("_odp_ishm_pool_alloc failed!\n");
		return ODPDRV_DEVICE_INVALID;
	}

	/* save and set dev init parameters and insert new device in list */
	dev->param = *param;
	dev->enumr_destroy_callback = NULL;
	dev->driver = NULL;
	dev->devio = NULL;
	dev->driver_data = NULL;
	dev_list_write_lock();
	dev->next = device_lst.head;
	device_lst.head = dev;
	dev_list_write_unlock();

	/* todo: probe for drivers */

	return (odpdrv_device_t)dev;
}

int odpdrv_device_destroy(odpdrv_device_t dev,
			  void (*callback)(void *enum_dev), uint32_t flags)
{
	_odpdrv_device_t *device = get_device(dev);
	_odpdrv_device_t *_dev;
	_odpdrv_device_t *target = NULL;

	if (dev == ODPDRV_DEVICE_INVALID) {
		ODP_ERR("Invalid device\n");
		return -1;
	}

	if (flags & ODPDRV_DEV_DESTROY_IMMEDIATE)
		ODP_ERR("ODPDRV_DEV_DESTROY_IMMEDIATE not supported yet\n");

	/* remove the device from the device list (but keep the device): */
	dev_list_write_lock();
	if (device == device_lst.head) {
		target = device;
		device_lst.head = device_lst.head->next;
	} else {
		_dev = device_lst.head;
		while (_dev) {
			if (_dev->next == device) {
				target = device;
				_dev->next = _dev->next->next;
				break;
			}
			_dev = _dev->next;
		}
	}
	dev_list_write_unlock();

	if (!target) {
		ODP_ERR("Unknown device (cannot be removed)!\n");
		return -1;
	}

	/* save the enumerator callback function which should be called
	 * when the driver is unbound (for gracious removal):
	 */
	target->enumr_destroy_callback = callback;

	/* unbind the driver from the device (if bound).
	 * The callback is always called, and only cares
	 * about IMMEDIATE flag.
	 */
	unbind_device_driver(target,
			     device_destroy_terminate,
			     (flags & ODPDRV_DEV_DESTROY_IMMEDIATE));

	return 0;
}

/* This function is called as a callback from the driver, when unbindind
 * a device from odpdrv_device_destroy()
 * just call the enumerator callback to cleanup the enumerator part
 * and free device memory */
static void device_destroy_terminate(odpdrv_device_t drv_device)
{
	_odpdrv_device_t *device = get_device(drv_device);
	void (*callback)(void *enum_dev);

	/* get the enumerator callback function */
	callback = device->enumr_destroy_callback;

	/* let the enumerator cleanup his part: */
	if (callback != NULL)
		callback(device->param.enum_dev);

	/* free device memory: */
	_odp_ishm_pool_free(list_elt_pool, device);
}

odpdrv_device_t *odpdrv_device_query(odpdrv_enumr_t enumr, const char *address)
{
	_odpdrv_device_t *dev;
	odpdrv_device_t *res;
	int index = 0;

	int size = sizeof(odpdrv_device_t); /* for the ODPDRV_DEVICE_INVALID */

	/* parse the list of device a first time to determine the size of
	 * the memory to be allocated:
	 */
	dev_list_read_lock();
	dev = device_lst.head;
	while (dev) {
		if ((dev->param.enumerator == enumr) &&
		    ((address == NULL) ||
		     (strcmp(dev->param.address, address) == 0)))
			size += sizeof(odpdrv_device_t);
		dev = dev->next;
	}

	/* then fill the list: */
	res = (odpdrv_device_t *)malloc(size);
	if (res == NULL)
		return NULL;

	dev = device_lst.head;
	while (dev) {
		if ((dev->param.enumerator == enumr) &&
		    ((address == NULL) ||
		     (strcmp(dev->param.address, address) == 0)))
			res[index++] = (odpdrv_device_t)dev;
		dev = dev->next;
	}
	dev_list_read_unlock();
	res[index] = ODPDRV_DEVICE_INVALID;

	return res; /* must be freed by caller! */
}

odpdrv_devio_t odpdrv_devio_register(odpdrv_devio_param_t *param)
{
	_odpdrv_devio_t *devio;

	/* parse the list of already registered devios to make
	 * sure no devio providing the same interface using th esame enumerator
	 * already exists:
	 */
	devio_list_read_lock();
	devio = devio_lst.head;
	while (devio) {
		if ((strncmp(param->api_name, devio->param.api_name,
			     ODPDRV_NAME_SIZE) == 0) &&
		    (strncmp(param->enumr_api_name, devio->param.enumr_api_name,
			     ODPDRV_NAME_SIZE) == 0)) {
			ODP_ERR("a devio providing interface '%s' for devices "
				"of type '%s' is already registered\n!",
				param->api_name, param->enumr_api_name);
			devio_list_read_unlock();
			return ODPDRV_DEVIO_INVALID;
		}
		devio = devio->next;
	}
	devio_list_read_unlock();

	/* allocate memory for the new devio:
	 * If init_global has not been done yet, then, we cannot allocate
	 * from any _ishm pool (ishm has not even been initialised at this
	 * stage...this happens when statically linked devios
	 * register: their __constructor__ function is run before main()
	 * is called). But any malloc performed here(before init_global)
	 * will be inherited by any odpthreads (process or pthreads) as we
	 * are still running in the ODP instantiation processes and all
	 * other processes are guaranteed to be descendent of this one...
	 * If init_global has been done, then we allocate from the _ishm pool
	 * to guarantee visibility from any ODP thread.
	 */

	if (init_global_status == UNDONE) {
		devio = malloc(sizeof(_odpdrv_devio_t));
		if (!devio)
			return ODPDRV_DEVIO_INVALID;
		devio->pool = NULL;
	} else {
		devio = _odp_ishm_pool_alloc(list_elt_pool,
					     sizeof(_odpdrv_devio_t));
		if (!devio) {
			ODP_ERR("_odp_ishm_pool_alloc failed!\n");
			return ODPDRV_DEVIO_INVALID;
		}
		devio->pool = list_elt_pool;
	}

	/* save init parameters and insert devio in list */
	devio->param = *param;
	devio_list_write_lock();
	devio->next = devio_lst.head;
	devio_lst.head = devio;
	devio_list_write_unlock();

	return (odpdrv_devio_t)devio;
}

odpdrv_driver_t odpdrv_driver_register(odpdrv_driver_param_t *param)
{
	_odpdrv_driver_t *driver;

	/* check for a few compulsory things: */
	if ((param->probe == NULL) ||
	    (param->unbind == NULL))
		return ODPDRV_DRIVER_INVALID;

	/* parse the list of already registered drivers to make
	 * sure no driver with same name already exists:
	 */
	driver_list_write_lock();
	driver = driver_lst.head;
	while (driver) {
		if ((strncmp(param->name, driver->param.name,
			     ODPDRV_NAME_SIZE) == 0)) {
			ODP_ERR("driver %s already registered!\n",
				param->name);
			driver_list_write_unlock();
			return ODPDRV_DRIVER_INVALID;
		}
		driver = driver->next;
	}

	/* allocate memory for the new driver:
	 * If init_global has not been done yet, then, we cannot allocate
	 * from any _ishm pool (ishm has not even been initialised at this
	 * stage...this happens when statically linked drivers
	 * register: their __constructor__ function is run before main()
	 * is called). But any malloc performed here(before init_global)
	 * will be inherited by any odpthreads (process or pthreads) as we
	 * are still running in the ODP instantiation processes and all
	 * other processes are guaranteed to be descendent of this one...
	 * If init_global has been done, then we allocate from the _ishm pool
	 * to guarantee visibility from any ODP thread.
	 */

	if (init_global_status == UNDONE) {
		driver = malloc(sizeof(_odpdrv_driver_t));
		if (!driver) {
			driver_list_write_unlock();
			return ODPDRV_DRIVER_INVALID;
		}
		driver->pool = NULL;
	} else {
		driver = _odp_ishm_pool_alloc(list_elt_pool,
					      sizeof(_odpdrv_driver_t));
		if (!driver) {
			ODP_ERR("_odp_ishm_pool_alloc failed!\n");
			driver_list_write_unlock();
			return ODPDRV_DRIVER_INVALID;
		}
		driver->pool = list_elt_pool;
	}

	/* save init parameters and insert driver in list */
	driver->param = *param;
	odp_ticketlock_init(&driver->probelock);
	driver->next = driver_lst.head;
	driver_lst.head = driver;
	driver_list_write_unlock();

	return (odpdrv_driver_t)driver;
}

/* Probe, if possible, the given driver with the given device:
 * The driver is probed if:
 * There exist a devio D such as
 * -The name and version of the API provided by D matches one of the requested
 *  devio {name,version} requested by the driver
 * -The enumerator's API (name and version) requested by D is provided
 * by the enumerator which enumerated the device.
 * This function will return zero if the above conditions where met by some
 * devio D and the driver probe function returns 0 (success).
 * The function will return -1 if some devio D were found, but the driver
 * returned a non-zero value when probed (for all of them).
 * The function will return -2 if no devio matching the above requirement was
 * found.
 * The function will return -3 if the device was already bound to a driver */
static int probe_device_driver(_odpdrv_device_t *dev, _odpdrv_driver_t *drv)
{
	int i;
	int ret = -2;
	_odpdrv_devio_t *devio;
	_odpdrv_enumr_t *enumr;
	_odpdrv_enumr_class_t *enumr_c;

	/* the device already has a driver?: end of story... */
	if (dev->driver)
		return -3;

	/* look at the different devio this driver can work with: */
	for (i = 0; i < ODPDRV_MAX_DEVIOS; i++) {
		/* look at each registered devios: */
		devio_list_read_lock();
		for (devio = devio_lst.head; devio; devio = devio->next) {
			/* if devio is no good for this driver, keep searching*/
			if ((strncmp(drv->param.devios[i].api_name,
				     devio->param.api_name,
				     ODPDRV_NAME_SIZE) != 0) ||
			    (drv->param.devios[i].api_version !=
			     devio->param.api_version))
				continue;

			/* give a chance to the devio to reject the device
			 * if it feels it should do so: */
			if (devio->param.probe &&
			    devio->param.probe((odpdrv_device_t)dev))
				continue;

			/* grab the device enumerator and its class: */
			enumr = get_enumr(dev->param.enumerator);
			enumr_c = get_enumr_class(enumr->param.enumr_class);

			/* if devio is no good for this dev, keep searching */
			if ((strncmp(devio->param.enumr_api_name,
				     enumr->param.api_name,
				     ODPDRV_NAME_SIZE) != 0) ||
				     (devio->param.enumr_api_version !=
					enumr->param.api_version))
				continue;

			/* seems we are good to probe the driver: */
			odp_ticketlock_lock(&drv->probelock);
			if (drv->param.probe((odpdrv_device_t)dev,
					     (odpdrv_devio_t)devio, i) == 0) {
				/* the driver accepts this device */
				odp_ticketlock_unlock(&drv->probelock);
				devio_list_read_unlock();
				ODP_DBG("driver %s will handle device %s(%s)\n",
					drv->param.name,
					dev->param.address,
					enumr_c->param.name);
				dev->driver = drv;
				dev->devio = devio;
				return 0;
			}
			odp_ticketlock_unlock(&drv->probelock);

			/* driver did not accept the device: keep searching */
			ret = -1;
		}
		devio_list_read_unlock();
	}
	return ret;
}

/* an empty callback is given to the driver on unprobe, if no real callback is
 * needed */
static void empty_unbind_callback(odpdrv_device_t odpdrv_dev ODP_UNUSED)
{
}

/* unbind the device driver from the device (i.e. "unprobe")
 * if the immediate flag is set, the unbind is requested to be immediate,
 * i.e. the driver is due to call the callback within its unbind function.
 * (if the flag is not set, the callback can be called later on from
 * another context. Immediate unbinding may be less graceful than
 * non immediate unbinding)
 * The callback function is called in all cases (even if the device was not
 * bound)
 */
static int unbind_device_driver(_odpdrv_device_t *dev,
				void (*callback)(odpdrv_device_t odpdrv_dev),
				uint32_t flags)
{
	_odpdrv_driver_t *drv;
	odpdrv_device_t odpdrv_dev = (odpdrv_device_t)dev;

	if (!callback)
		callback = empty_unbind_callback;

	drv = dev->driver;
	if (!drv) { /* nothing to do */
		callback(odpdrv_dev);
		return 0;
	}

	/* note that we assure that a given driver will not be bound/unbound
	 * concurrentely - but this does not cover the callback */
	odp_ticketlock_lock(&drv->probelock);
	if (drv->param.unbind(odpdrv_dev, callback, flags)) {
		ODP_DBG("driver %s could not release device %s\n",
			drv->param.name,
			dev->param.address);
		odp_ticketlock_unlock(&drv->probelock);
		return -1;
	}

	/* unbind succeeded */
	dev->driver = NULL;
	dev->devio = NULL;
	odp_ticketlock_unlock(&drv->probelock);
	return 0;
}

/* try to find a driver for the given device, trying all possible registered
 * drivers against it:
 * returns 0 on success or -1 on error
 */
static int probe_device(_odpdrv_device_t *dev)
{
	_odpdrv_driver_t *driver;
	int ret = -1;

	/* go through the list of registered drivers: */
	driver_list_read_lock();
	driver = driver_lst.head;
	while (driver) {
		if (probe_device_driver(dev, driver) == 0) {
			ret = 0;
			break;
		}
		driver = driver->next;
	}
	driver_list_read_unlock();

	return ret;
}

/* try to find a driver for all the registered devices, trying all possible
 * drivers-devices combination
 */
static void probe_all(void)
{
	_odpdrv_device_t *dev;

	dev_list_read_lock();
	dev = device_lst.head;
	while (dev) {
		(void)probe_device(dev);
		dev = dev->next;
	}
	dev_list_read_unlock();
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

	/* probe drivers for all devices */
	probe_all();
}

void odpdrv_device_set_data(odpdrv_device_t dev, void *data)
{
	_odpdrv_device_t *_dev;

	_dev = get_device(dev);
	_dev->driver_data = data;
}

void *odpdrv_device_get_data(odpdrv_device_t dev)
{
	_odpdrv_device_t *_dev;

	_dev = get_device(dev);
	return _dev->driver_data;
}

int odpdrv_print_all(void)
{
	_odpdrv_enumr_class_t *enumr_c;
	_odpdrv_enumr_t *enumr;
	_odpdrv_device_t *dev;
	_odpdrv_devio_t *devio;
	_odpdrv_driver_t *driver;

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

	/* print the list of registered devices: */
	dev_list_read_lock();
	dev = device_lst.head;
	ODP_DBG("The following devices have been registered:\n");
	while (dev) {
		enumr = get_enumr(dev->param.enumerator);
		enumr_c = get_enumr_class(enumr->param.enumr_class);
		ODP_DBG(" device: address: %s, from enumerator class: %s "
			"  API: %s, Version: %" PRIu32 ", "
			" handled by driver %s, with devio API: %s "
			" (version %" PRIu32 ")\n",
			dev->param.address,
			enumr_c->param.name,
			enumr->param.api_name,
			enumr->param.api_version,
			dev->driver ? dev->driver->param.name : "<none>",
			dev->devio ? dev->devio->param.api_name : "<none>",
			dev->devio ? dev->devio->param.api_version : 0);
		dev = dev->next;
	}
	dev_list_read_unlock();

	/* print the list of registered devios: */
	devio_list_read_lock();
	devio = devio_lst.head;
	ODP_DBG("The following dev IOs have been registered:\n");
	while (devio) {
		ODP_DBG(" devio providing interface: '%s' (version %d) for "
			" devices of type '%s' (version %d)\n",
			devio->param.api_name,
			devio->param.api_version,
			devio->param.enumr_api_name,
			devio->param.enumr_api_version);
		devio = devio->next;
	}
	devio_list_read_unlock();

	/* print the list of registered drivers: */
	driver_list_read_lock();
	driver = driver_lst.head;
	ODP_DBG("The following dev drivers have been registered:\n");
	while (driver) {
		ODP_DBG(" driver: '%s'\n",
			driver->param.name);
		driver = driver->next;
	}
	driver_list_read_unlock();

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
	odp_rwlock_recursive_init(&device_lst.lock);
	odp_rwlock_recursive_init(&devio_lst.lock);
	odp_rwlock_recursive_init(&driver_lst.lock);

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
	_odpdrv_devio_t *devio;
	_odpdrv_enumr_class_t *enumr_c;
	_odpdrv_enumr_t *enumr;
	_odpdrv_device_t *dev;
	_odpdrv_driver_t *driver;

	if (init_global_status == UNDONE)
		return 0;

	/* unbind any driver from any device: */
	dev_list_read_lock();
	dev = device_lst.head;
	while (dev) {
		unbind_device_driver(dev, NULL, ODPDRV_DEV_DESTROY_IMMEDIATE);
		dev = dev->next;
	}
	dev_list_read_unlock();

	/* and remove all registered drivers: */
	driver_list_read_lock();
	while (driver_lst.head) {
		driver = driver_lst.head;
		if (driver->param.remove) {
			if (driver->param.remove())
				ODP_ERR("driver removal indicated failure!\n");
		}
		driver_lst.head = driver->next;
		if (driver->pool)
			_odp_ishm_pool_free(list_elt_pool, driver);
		else
			free(driver);
	}

	/* remove all devios which are registered: */
	devio_list_write_lock();
	while (devio_lst.head) {
		devio = devio_lst.head; /* run removal function, if any */
		if (devio->param.remove) {
			if (devio->param.remove())
				ODP_ERR("devio removal indicated failure!\n");
		}
		devio_lst.head = devio->next;
		if (devio->pool)
			_odp_ishm_pool_free(list_elt_pool, devio);
		else
			free(devio);
	}
	devio_list_write_unlock();

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
