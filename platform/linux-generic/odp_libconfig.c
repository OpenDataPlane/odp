/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <libconfig.h>

#include <odp/api/version.h>
#include <odp_global_data.h>
#include <odp_debug_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_libconfig_config.h>

int _odp_libconfig_init_global(void)
{
	const char *filename;
	const char *vers;
	const char *vers_rt;
	const char *impl;
	const char *impl_rt;
	config_t *config = &odp_global_ro.libconfig_default;
	config_t *config_rt = &odp_global_ro.libconfig_runtime;
	const char *impl_field = "odp_implementation";
	const char *vers_field = "config_file_version";

	config_init(config);
	config_init(config_rt);

	if (!config_read_string(config, config_builtin)) {
		ODP_ERR("Failed to read default config: %s(%d): %s\n",
			config_error_file(config), config_error_line(config),
			config_error_text(config));
		goto fail;
	}

	filename = getenv("ODP_CONFIG_FILE");
	if (filename == NULL)
		return 0;

	ODP_PRINT("ODP CONFIG FILE: %s\n", filename);

	if (!config_read_file(config_rt, filename)) {
		ODP_PRINT("  ERROR: failed to read config file: %s(%d): %s\n\n",
			  config_error_file(config_rt),
			  config_error_line(config_rt),
			  config_error_text(config_rt));
		goto fail;
	}

	/* Check runtime configuration's implementation name and version */
	if (!config_lookup_string(config, impl_field, &impl) ||
	    !config_lookup_string(config_rt, impl_field, &impl_rt)) {
		ODP_PRINT("  ERROR: missing mandatory field: %s\n\n",
			  impl_field);
		goto fail;
	}
	if (!config_lookup_string(config, vers_field, &vers) ||
	    !config_lookup_string(config_rt, vers_field, &vers_rt)) {
		ODP_PRINT("  ERROR: missing mandatory field: %s\n\n",
			  vers_field);
		goto fail;
	}
	if (strcmp(impl, impl_rt)) {
		ODP_PRINT("  ERROR: ODP implementation name mismatch:\n"
			  "    Expected: \"%s\"\n"
			  "    Found:    \"%s\"\n\n", impl, impl_rt);
		goto fail;
	}
	if (strcmp(vers, vers_rt)) {
		ODP_PRINT("  ERROR: config file version number mismatch:\n"
			  "    Expected: \"%s\"\n"
			  "    Found:    \"%s\"\n\n", vers, vers_rt);
		goto fail;
	}

	return 0;
fail:
	ODP_ERR("Config file failure\n");
	config_destroy(config);
	config_destroy(config_rt);
	return -1;
}

int _odp_libconfig_term_global(void)
{
	config_destroy(&odp_global_ro.libconfig_default);
	config_destroy(&odp_global_ro.libconfig_runtime);

	return 0;
}

int _odp_libconfig_lookup_int(const char *path, int *value)
{
	int ret_def = CONFIG_FALSE;
	int ret_rt = CONFIG_FALSE;

	ret_def = config_lookup_int(&odp_global_ro.libconfig_default, path,
				    value);

	/* Runtime option overrides default value */
	ret_rt = config_lookup_int(&odp_global_ro.libconfig_runtime, path,
				   value);

	return  (ret_def == CONFIG_TRUE || ret_rt == CONFIG_TRUE) ? 1 : 0;
}

int _odp_libconfig_lookup_array(const char *path, int value[], int max_num)
{
	const config_t *config;
	config_setting_t *setting;
	int num, i, j;
	int num_out = 0;

	for (j = 0; j < 2; j++) {
		if (j == 0)
			config = &odp_global_ro.libconfig_default;
		else
			config = &odp_global_ro.libconfig_runtime;

		setting = config_lookup(config, path);

		/* Runtime config may not define the array, whereas
		 * the default config has it always defined. When the array
		 * is defined, it must be correctly formatted. */
		if (setting == NULL)
			continue;

		if (config_setting_is_array(setting) == CONFIG_FALSE)
			return 0;

		num = config_setting_length(setting);

		if (num <= 0 || num > max_num)
			return 0;

		for (i = 0; i < num; i++)
			value[i] = config_setting_get_int_elem(setting, i);

		num_out = num;
	}

	/* Number of elements copied */
	return num_out;
}

static int lookup_int(config_t *cfg,
		      const char *base_path,
		      const char *local_path,
		      const char *name,
		      int *value)
{
	char path[256];

	if (local_path) {
		snprintf(path, sizeof(path), "%s.%s.%s", base_path,
			 local_path, name);
		if (config_lookup_int(cfg, path, value) == CONFIG_TRUE)
			return 1;
	}

	snprintf(path, sizeof(path), "%s.%s", base_path, name);
	if (config_lookup_int(cfg, path, value) == CONFIG_TRUE)
		return 1;

	return 0;
}

int _odp_libconfig_lookup_ext_int(const char *base_path,
				  const char *local_path,
				  const char *name,
				  int *value)
{
	if (lookup_int(&odp_global_ro.libconfig_runtime,
		       base_path, local_path, name, value))
		return 1;

	if (lookup_int(&odp_global_ro.libconfig_default,
		       base_path, local_path, name, value))
		return 1;

	return 0;
}
