/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV driver
 */

#ifndef ODPDRV_DRIVER_H_
#define ODPDRV_DRIVER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
* @addtogroup odpdrv_driver
* @details
* enumerator and driver interface to ODP
*
*  1) ODP loads the different modules (i.e. it loads shared libraries, *.so).
*     In the context of drivers, shared libraries may contain enumerators,
*     drivers and devios. These register in step 2.
*
*  2)
* @code
*      odpdrv_enumr_class_register(int (probe*)()...)
*      ----------------------------------------------------------->
*      odpdrv_driver_register(int (probe*)()...)
*      ----------------------------------------------------------->
*      odpdrv_devio_register()
*      ----------------------------------------------------------->
* @endcode
*  A number of device_enumerator_classes are registered at the ODP startup.
*  Many classes are expected: static, ACPI, PCI, switchdev, virtual, DPAA2...
*  A number of drivers also register to ODP (passing their own probe function).
*  A number of device IO may also register to ODP (defining available devices
*  interfaces).
*
*  3)  ODP calls the probe function of each enumerator class <BR>
* @code
*      enumerator class probe()
*      <-----------------------------------------------------------
*      odpdrv_emum_register(int (probe*)()...)
*      ----------------------------------------------------------->
*      ----------------------------------------------------------->
*      ----------------------------------------------------------->
*      odpdrv_devio_register(...)
*      ----------------------------------------------------------->
*      ----------------------------------------------------------->
*      ----------------------------------------------------------->
* @endcode
*  ODP calls the probe function of each registered enumerator_class.
*  This result in the enumerator_class registering some
*  enumerators (instances of the class) by calling
*  odpdrv_emumerator_register() for each instance.
*  A given enumerator_class may create many enumerators based on its platform:
*  For instance Linux defines a number of PCI domains that can be viewed as
*  multiple PCI enumerators. In addition, it could be considered that each PCI
*  root of each processor socket in a NUMA environment has its own PCI
*  enumerator.
*  For enumerator class PCI, there could be one instance for each PCI
*  domain.
*  The devios delivered with their enumerator may also register at this stage.
*
* 4)
* @code
*      enumerator probe()
*      <-----------------------------------------------------------
*      odpdrv_device_create()
*      ----------------------------------------------------------->
*      odpdrv_device_create()
*      ----------------------------------------------------------->
*      odpdrv_device_create()
*      ----------------------------------------------------------->
* @endcode
*  For each enumerator instance, odp calls the probe function.
*  This will trigger devices creation (Enumerators calls odpdrv
*  odpdrv_device_create() for each new device). Enumerators are allowed
*  to call odpdrv_device_create() at any time once they have been probed
*  (hotplug). They also may call odpdrv_device_destroy() if needed.
*
*  5) The driver framework calls the drivers probe(D,I) functions of the
*  drivers, with device D and devio I as parameter, assuming that:
*	-devio I was on the driver supported list of devio (and version matches)
*	-the devio I is registered and found its enumerator interface(E) api
*	 (name and version)
*	-device D was enumerated by an enumerator providing interface E.
*  The return value of the driver probe function tells whether the driver
*  can handle the device or not.
*
* @{
*/

/* Forward declarations for a top down description of structures */
/** Parameters for enumerator class registration */
typedef struct odpdrv_enumr_class_param_t odpdrv_enumr_class_param_t;
/** Parameters for enumerator registration */
typedef struct odpdrv_enumr_param_t odpdrv_enumr_param_t;
/** Parameters for new device creation */
typedef struct odpdrv_device_param_t odpdrv_device_param_t;
/** Parameters for devio registration*/
typedef struct odpdrv_devio_param_t odpdrv_devio_param_t;
/** Parameters for driver registration*/
typedef struct odpdrv_driver_param_t odpdrv_driver_param_t;

/**
 * @typedef odpdrv_enumr_class_t
 * ODPDRV enumerator class, such as PCI.
 */
/**
 * @def ODPDRV_ENUMR_CLASS_INVALID
 * Invalid odpdrv enumerator class
 */

/**
 * @typedef odpdrv_enumr_t
 * ODPDRV enumerator. Instance of odpdrv_enumr_class_t.
 */
/**
 * @def ODPDRV_ENUMR_INVALID
 * Invalid odpdrv enumerator
 */

/**
 * @typedef odpdrv_device_t
 * ODPDRV device. Created and destroyed by enumerators
 */
/**
 * @def ODPDRV_DEVICE_INVALID
 * Invalid odpdrv device
 */

/**
 * @typedef odpdrv_devio_t
 * ODPDRV device IO interface.
 */
/**
 * @def ODPDRV_DEVIO_INVALID
 * Invalid odpdrv device IO
 */

/**
 * @typedef odpdrv_driver_t
 * ODPDRV device driver.
 */
/**
 * @def ODPDRV_DRIVER_INVALID
 * Invalid odpdrv driver
 */

/** Maximum size for driver and enumerator names */
#define ODPDRV_NAME_SIZE 32

/** Maximum size for the enumerator dependent address */
#define ODPDRV_NAME_ADDR_SZ 64

/** The maximum number of interfaces a driver may support */
#define ODPDRV_MAX_DEVIOS 3

/**
* Parameters to be given at enumerator class registration
*/
struct odpdrv_enumr_class_param_t {
	/** Enumerator name: mostly used for debug purpose.
	 * Name must be unique (e.g. "PCI-DPAA2")
	 */
	char name[ODPDRV_NAME_SIZE];

	/** Probe function:
	 * Called by ODP to get the enumerator class instances registered
	 */
	int (*probe)(void);

	/** Remove function:
	 * Free whatever resource the class may have allocated.
	 */
	int (*remove)(void);
};

/**
* Parameter to be given at enumerator (instance) registration
*/
struct odpdrv_enumr_param_t {
	/** Class
	 * Identifies the class of the enumerator
	 */
	odpdrv_enumr_class_t enumr_class;

	/** Enumerator api_name and version are used by the devio
	 * to make sure the device can be accessed:
	 * E.g. "PCI"
	 * The format of the enum_dev part for the odpdrv_device_param_t
	 * structure is identified by the api-name and version below
	 */
	char api_name[ODPDRV_NAME_SIZE];
	uint32_t api_version; /**<< the version of the provided API */

	/** Probe function:
	 * Called by ODP when it is ready for device creation/deletion
	 * returns an negative value on error or 0 on success.
	 */
	int (*probe)(void);

	/** Remove function:
	 * destroy all enumerated devices and release all resources
	 */
	int (*remove)(void);

	/** Register event notifier function for hotplug events:
	 * register_notifier(fcnt,event_mask) registers fcnt as a callback when
	 * one of the event specified in event_mask occurs.
	 */
	int (*register_notifier)(void (*event_handler) (uint64_t event),
				 int64_t event_mask);
};

/* The following events are supported by enumerators */
#define ODPDRV_ENUM_EV_REMOVED	0x0000000000000001 /**<< remove event */

/** This structure defines a generic enumerated device, or actually the
* common part between all devices, the enumerator specific part being pointed
* by the enum_dev field below.
*/
struct odpdrv_device_param_t {
	/** enumerator
	 * enumerator which enumerated the device: as returned by
	 * odpdrv_enumr_register
	 * devices with parents get destroyed when the parents dies.
	 */
	odpdrv_enumr_t enumerator;

	/** Device address:
	 * An enumerator dependent string giving the device address,
	 * e.g. "0000.23.12.1" for PCI domain 0, bus 23, device 12, function 1.
	 * This string identifies the device uniquely.
	 */
	char address[ODPDRV_NAME_ADDR_SZ];

	/** Enumerator dependent part
	 * This part is allocated by the enumerator and is enumerator dependent
	 * (i.e. different devices types will have different contents for
	 * enum_dev).
	 */
	void *enum_dev;
};

/**
 * Parameter to be given at devio registration
 */
struct odpdrv_devio_param_t {
	/** Devio name
	 * Identifies devio interface implemented by this devio
	 * (i.e:many devios may have the same name, but none of those
	 * with same provided interface should refer to a common enumerator
	 * class)
	 */
	char api_name[ODPDRV_NAME_SIZE];
	uint32_t api_version; /**<< the version of the provided API */

	/** Enumerator interface name and version
	 * The enumerator interface this devio needs.
	 */
	char enumr_api_name[ODPDRV_NAME_SIZE];
	uint32_t enumr_api_version; /**<< required enumerator API version */

	/** Probe function:
	 * Tell whether this devio can handle the given device.
	 * The devio is hence given a chance to reject a given device for
	 * any reason. No binding occurs here. binding occurs when the
	 * driver is probed.
	 * returns 0 if this devio can handle the given device, or a negative
	 * value if not.
	 * If left to NULL, a 0 returned value is assumed
	 */
	int (*probe)(odpdrv_device_t dev);

	/** Remove function:
	 * Should destroy the memory allocated for ops and anything else
	 * under it, or any resource for this devio.
	 * Returns 0 on success or a negative value on error.
	 */
	int (*remove)(void);

	/** Ops
	 * Pointer to a devio ops structure (specific to each devio)
	 */
	void *ops;
};

/**
* Parameter to be given at driver registration
*/
struct odpdrv_driver_param_t {
	/** Driver name
	 * The driver name (the pair {driver-name, enum-api-name} must
	 * be unique)
	 */
	char name[ODPDRV_NAME_SIZE];

	/** Supported devios:
	 * The list of supported devio: one of the following devio
	 * (with correct version) must be available for the driver to work:
	 */
	struct {
		char api_name[ODPDRV_NAME_SIZE]; /**<< devio API name */
		uint32_t   api_version; /**<< devio API version */
	} devios[ODPDRV_MAX_DEVIOS];

	/** Probe function:
	 * Called by ODP to see if the driver can drive a given device
	 * -dev the device to be probed
	 * -devio is the devio to be used.
	 * -devio_idx actually tells which devio was selected: it is the
	 * index in the devios array above.
	 */
	int (*probe)(odpdrv_device_t dev, odpdrv_devio_t devio, int devio_idx);

	/** unbind function:
	 * Only called with devices whose probe() returned true
	 *
	 * dev: the device to unbind
	 * callback: if flag ODPDRV_DRV_UNBIND_IMMEDIATE is not specified,
	 *  unbind should be attempted gracefully, meaning that some IO may need
	 *  to terminate before the driver is really unbound from the device:
	 *  In this case (when the flag is not set), the driver is due to call
	 *  the callback function when the driver is unbound from the device.
	 *  This callback may occurs within the unbind() call if the driver
	 *  does unbind immediately.
	 *  If the ODPDRV_DRV_UNBIND_IMMEDIATE is specified, the driver is due
	 *  to release the device immediately (poosibly less gracefully).
	 *  The callback must be called immediately in this case.
	 */
	int (*unbind)(odpdrv_device_t dev,
		      void (*callback)(odpdrv_device_t dev),
		      uint32_t flags);

	/** remove function:
	 * remove any resource taken by the driver. Called when the driver
	 * itself is to be removed, i.e. after all devices are unbound
	 * Can be set to NULL if the driver has nothing to release.
	 *
	 */
	int (*remove)(void);
};

/** The callback function must be called mmediately by the current ODP thread */
#define ODPDRV_DRV_UNBIND_IMMEDIATE	0x00000001

/**
* Register an enumerator class.
* Each enumerator class calls this function at init time.
* (probably using gcc/clang * __constructor__ attribute.)
*
* @param param Pointer to a enumerator class registration structure.
* @return an enumerator class handle or ODPDRV_ENUMR_CLASS_INVALID on error.
* On errors, enumerators classes should release allocated resources and return.
*/
odpdrv_enumr_class_t odpdrv_enumr_class_register(odpdrv_enumr_class_param_t
						 *param);

/**
* Register an enumerator.
* Each enumerator calls this function at init time.
* (probably using gcc/clang * __constructor__ attribute.)
*
* @param param Pointer to a enumerator registration parameter structure.
* @return an enumerator handle or ODPDRV_ENUMR_INVALID on error.
* On errors, enumerators should release allocated resources and return.
*/
odpdrv_enumr_t odpdrv_enumr_register(odpdrv_enumr_param_t *param);

/**
* Create a device
* Called by each enumerator at probe time, or anytime later, for each
* new created device
* @param param Pointer to a device parameter structure.
* @return an odpdrv devuice handle or ODPDRV_DEVICE_INVALID on error.
*/
odpdrv_device_t odpdrv_device_create(odpdrv_device_param_t *param);

/**
* Destroy a device
* Called by each enumerator after probe time, for each device to be
* destroyed.
* Destroying a device may require tearing down a driver and waiting for some IO
* to terminate: The device destruction is therefore done in 2 steps:
* Calling this function starts the device destruction: when the device has
* no driver attached any longer, ODP calls the provided callback()
* function  which should free the enumerator-allocated resources for
* this device.
* If the flag ODPDRV_DEV_DESTROY_IMMEDIATE is given, the device destruction
* is immediate, i.e. the callback function is guaranteed to be called by the
* same ODP thread: This might however not let the time for the bound driver
* (if any) to terminate gracefully. This would typically be used at ODP
* terminaison. By default, the callback may be called later, when the driver
* has gracefully terminated, hence possibly from another ODP thread.
* @param dev A odpdrv device handle as returned by odpdrv_device_create.
* @param callback a pointer to a function to be called when the device is
*        freed (no more driver). The parameter to the callback function is
*	 the pointer to the enumerator specific part of the device as provided
*	 at device creation time (void *enum_dev). The callback function
*	 should release these resources.
* @param flags 0 or ODPDRV_DEV_DESTROY_IMMEDIATE for immediate shut down
* @return 0 on success or a negative value on error. On error, the callback
* function is not called.
*/
int odpdrv_device_destroy(odpdrv_device_t dev,
			  void (*callback)(void *enum_dev), uint32_t flags);

/** The callback function must be called by the current ODP thread */
#define ODPDRV_DEV_DESTROY_IMMEDIATE	0x00000001

/** query for a list of devices
 * Enumerators are responsable for device creation and destruction.
 * Upon request, ODP can build a list of devices belonging to a given enumerator
 * and possibly having a specific address.
 * This function builds this list.
 * @param enumr The enumerator which created the device
 * @param address The device address (or NULL if don't care)
 * @return A malloc'd ODPDRV_DEVICE_INVALID terminated array of odpdrv_device_t
 *         This array MUST BE FREED by the caller!
 */
odpdrv_device_t *odpdrv_device_query(odpdrv_enumr_t enumr, const char *address);

/**
* Register an devio.
* Each devio calls this function at init time.
* (probably using gcc/clang * __constructor__ attribute.)
*
* @param param Pointer to a devio registration structure.
* @return an odpdrv_devio_t handle or ODPDRV_DEVIO_INVALID on error.
*/
odpdrv_devio_t odpdrv_devio_register(odpdrv_devio_param_t *param);

/**
* Register a Driver.
* Each driver calls this function at init time.
* (probably using gcc/clang * __constructor__ attribute.)
*
* @param param Pointer to a driver registration structure.
* @return an odpdrv_driver_t handle or ODPDRV_DRIVER_INVALID on error.
* On errors, drivers should release allocated resources and return.
*/
odpdrv_driver_t odpdrv_driver_register(odpdrv_driver_param_t *param);

/**
* Print (ODP_DBG) the driver interface status (debug).
*
* @return 0 on success, less than zero on error (inconsistency detected)
*/
int odpdrv_print_all(void);

/**
* @}
*/

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
