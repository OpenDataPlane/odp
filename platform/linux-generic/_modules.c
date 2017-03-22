/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_config_internal.h>

#include <odp/api/std_types.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <drv_driver_internal.h>
#include <libconfig.h>
#include <dlfcn.h>

static int load_modules(void)
{
	config_t *cf;
	const config_setting_t *modules_section;
	int module_count;
	int i;
	const char *module_name;

	cf = &odp_global_data.configuration;
	modules_section = config_lookup(cf, "module.modules");
	if (!modules_section)
		return 0;

	module_count = config_setting_length(modules_section);
	if (!module_count)
		return 0;

	for (i = 0; i < module_count; i++) {
		module_name = config_setting_get_string_elem(modules_section,
							     i);
		if (dlopen(module_name, RTLD_NOW) == NULL) {
			ODP_ERR("dlopen failed for %s: %s\n",
				module_name, dlerror());
			return -1;
		}
		ODP_DBG("module %s loaded.\n", module_name);
	}

	/* give a chance top the driver interface to probe for new things: */
	_odpdrv_driver_probe_drv_items();

	return 0;
}

int _odp_modules_init_global(void)
{
	/* load modules (enumerator and drivers...) */
	if (load_modules())
		return -1;

	return 0;
}
