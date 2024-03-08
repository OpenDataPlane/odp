/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

/**
 * @file
 *
 * Common libconfig functions
 */

#ifndef ODP_LIBCONFIG_INTERNAL_H_
#define ODP_LIBCONFIG_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

int _odp_libconfig_init_global(void);
int _odp_libconfig_term_global(void);

int _odp_libconfig_lookup_int(const char *path, int *value);
int _odp_libconfig_lookup_str(const char *path, char *value,
			      unsigned int str_size);
int _odp_libconfig_lookup_array(const char *path, int value[], int max_num);
int _odp_libconfig_lookup_array_str(const char *path, char **value,
				    int max_count, unsigned int max_str);

int _odp_libconfig_lookup_ext_int(const char *base_path,
				  const char *local_path,
				  const char *name,
				  int *value);

int _odp_libconfig_print(void);

#ifdef __cplusplus
}
#endif

#endif
