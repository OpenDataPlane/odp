/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp/api/init.h>
#include <odp_debug_internal.h>
#include <odp/api/debug.h>
#include <unistd.h>
#include <odp_internal.h>
#include <odp_schedule_if.h>
#include <string.h>
#include <libconfig.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/limits.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define _ODP_FILES_FMT "odp-%d-"
#define _ODP_TMPDIR    "/tmp"

/* the name of the ODP configuration file: */
#define CONFIGURATION_FILE_ENV_NONE "none"
#define CONFIGURATION_FILE "odp.conf"
#define CONFIGURATION_FILE_USR ("." CONFIGURATION_FILE)
#define CONFIGURATION_FILE_SYS (SYSCONFDIR "/" CONFIGURATION_FILE)

/* the ODP configuration file name can also be oveerwritten by env. variable: */
#define ODP_SYSCONFIG_FILE_ENV "ODP_SYSCONFIG_FILE"

struct odp_global_data_s odp_global_data;

/* remove all files staring with "odp-<pid>" from a directory "dir" */
static int cleanup_files(const char *dirpath, int odp_pid)
{
	struct dirent *e;
	DIR *dir;
	char prefix[PATH_MAX];
	char *fullpath;
	int d_len = strlen(dirpath);
	int p_len;
	int f_len;

	dir = opendir(dirpath);
	if (!dir) {
		/* ok if the dir does not exist. no much to delete then! */
		ODP_DBG("opendir failed for %s: %s\n",
			dirpath, strerror(errno));
		return 0;
	}
	snprintf(prefix, PATH_MAX, _ODP_FILES_FMT, odp_pid);
	p_len = strlen(prefix);
	while ((e = readdir(dir)) != NULL) {
		if (strncmp(e->d_name, prefix, p_len) == 0) {
			f_len = strlen(e->d_name);
			fullpath = malloc(d_len + f_len + 2);
			if (fullpath == NULL) {
				closedir(dir);
				return -1;
			}
			snprintf(fullpath, PATH_MAX, "%s/%s",
				 dirpath, e->d_name);
			ODP_DBG("deleting obsolete file: %s\n", fullpath);
			if (unlink(fullpath))
				ODP_ERR("unlink failed for %s: %s\n",
					fullpath, strerror(errno));
			free(fullpath);
		}
	}
	closedir(dir);

	return 0;
}

/* read the odp configuration file
 *
 * the configuration file is read from:
 * 1) Wherever env variable ODP_SYSCONFIG_FILE says (or "none")
 * 2) ./odp.conf
 * 3) the @sysconfig@/odp.conf
 * (checked in reverse order overwritting each-other)
 * So the environment variable setting supperseeds any other file.
 * If the environment variable exists and set to the string "none"
 * the configuration file reading is inibited (used to prevent
 * test which do not need a file to read the user or system files)
 */
static int read_configfile(void)
{
	config_t *cf;
	const char *config_filename;
	char user_config_filename[PATH_MAX];
	char *env_config_filename;

	/* initialize and read the configuration file if any: */
	cf = &odp_global_data.configuration;
	config_init(cf);
	config_filename = NULL;
	/* check if the system config file can be reached :*/
	if (access(CONFIGURATION_FILE_SYS, R_OK) != -1)
		config_filename = CONFIGURATION_FILE_SYS;
	/* check if the user config file can be reached (overwrite if so) :*/
	strncpy(user_config_filename, getenv("HOME"), PATH_MAX);
	if (user_config_filename[0]) {
		strncat(user_config_filename, "/", PATH_MAX);
		strncat(user_config_filename, CONFIGURATION_FILE_USR, PATH_MAX);
		if ((access(user_config_filename, R_OK) != -1))
			config_filename = user_config_filename;
	}
	/* check if other config file is specified via env (overwrite if so):*/
	env_config_filename = getenv(ODP_SYSCONFIG_FILE_ENV);
	if (env_config_filename) {
		/* none means "read no file": */
		if (!strcmp(env_config_filename, CONFIGURATION_FILE_ENV_NONE))
			return 0;
		if (access(env_config_filename, R_OK) != -1) {
			config_filename = env_config_filename;
		} else {
			ODP_ERR("Cannot read ODP configurattion file %s "
				"(set by env variable "
				ODP_SYSCONFIG_FILE_ENV ")\n",
				env_config_filename);
			config_filename = NULL;
			return -1;
		}
	}
	if (config_filename) {
		ODP_DBG("Reading configuration file: %s\n", config_filename);
		if (!config_read_file(cf, config_filename)) {
#if defined(LIBCONFIG_VER_MAJOR) && LIBCONFIG_VER_MAJOR >= 1 && \
				    LIBCONFIG_VER_MINOR >= 4
			ODP_ERR("%s:%d - %s\n",
				config_error_file(cf),
				config_error_line(cf),
				config_error_text(cf));
#else
			ODP_ERR("config_read_file\n");
#endif
			config_destroy(cf);
			return -1;
		}
	}

	return 0;
}

void odp_init_param_init(odp_init_t *param)
{
	memset(param, 0, sizeof(odp_init_t));
}

int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params ODP_UNUSED)
{
	char *hpdir;

	memset(&odp_global_data, 0, sizeof(struct odp_global_data_s));
	odp_global_data.main_pid = getpid();

	enum init_stage stage = NO_INIT;
	odp_global_data.log_fn = odp_override_log;
	odp_global_data.abort_fn = odp_override_abort;

	if (params != NULL) {
		if (params->log_fn != NULL)
			odp_global_data.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_data.abort_fn = params->abort_fn;
	}

	cleanup_files(_ODP_TMPDIR, odp_global_data.main_pid);

	if (read_configfile())
		goto init_failed;

	if (odp_cpumask_init_global(params)) {
		ODP_ERR("ODP cpumask init failed.\n");
		goto init_failed;
	}
	stage = CPUMASK_INIT;

	if (odp_time_init_global()) {
		ODP_ERR("ODP time init failed.\n");
		goto init_failed;
	}
	stage = TIME_INIT;

	if (odp_system_info_init()) {
		ODP_ERR("ODP system_info init failed.\n");
		goto init_failed;
	}
	hpdir = odp_global_data.hugepage_info.default_huge_page_dir;
	/* cleanup obsolete huge page files, if any */
	if (hpdir)
		cleanup_files(hpdir, odp_global_data.main_pid);
	stage = SYSINFO_INIT;

	if (_odp_fdserver_init_global()) {
		ODP_ERR("ODP fdserver init failed.\n");
		goto init_failed;
	}
	stage = FDSERVER_INIT;

	if (_odp_ishm_init_global()) {
		ODP_ERR("ODP ishm init failed.\n");
		goto init_failed;
	}
	stage = ISHM_INIT;

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		goto init_failed;
	}
	stage = THREAD_INIT;

	if (odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		goto init_failed;
	}
	stage = POOL_INIT;

	if (queue_fn->init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		goto init_failed;
	}
	stage = QUEUE_INIT;

	if (sched_fn->init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		goto init_failed;
	}
	stage = SCHED_INIT;

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		goto init_failed;
	}
	stage = PKTIO_INIT;

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		goto init_failed;
	}
	stage = TIMER_INIT;

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		goto init_failed;
	}
	stage = CRYPTO_INIT;

	if (odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		goto init_failed;
	}
	stage = CLASSIFICATION_INIT;

	if (odp_tm_init_global()) {
		ODP_ERR("ODP traffic manager init failed\n");
		goto init_failed;
	}
	stage = TRAFFIC_MNGR_INIT;

	if (_odp_int_name_tbl_init_global()) {
		ODP_ERR("ODP name table init failed\n");
		goto init_failed;
	}
	stage = NAME_TABLE_INIT;

	if (_odp_modules_init_global()) {
		ODP_ERR("ODP modules init failed\n");
		goto init_failed;
	}

	*instance = (odp_instance_t)odp_global_data.main_pid;

	return 0;

init_failed:
	_odp_term_global(stage);
	return -1;
}

int odp_term_global(odp_instance_t instance)
{
	if (instance != (odp_instance_t)odp_global_data.main_pid) {
		ODP_ERR("Bad instance.\n");
		return -1;
	}
	return _odp_term_global(ALL_INIT);
}

int _odp_term_global(enum init_stage stage)
{
	int rc = 0;

	switch (stage) {
	case ALL_INIT:
	case MODULES_INIT:
	case NAME_TABLE_INIT:
		if (_odp_int_name_tbl_term_global()) {
			ODP_ERR("Name table term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TRAFFIC_MNGR_INIT:
		if (odp_tm_term_global()) {
			ODP_ERR("TM term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CLASSIFICATION_INIT:
		if (odp_classification_term_global()) {
			ODP_ERR("ODP classification term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (odp_crypto_term_global()) {
			ODP_ERR("ODP crypto term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIMER_INIT:
		if (odp_timer_term_global()) {
			ODP_ERR("ODP timer term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case PKTIO_INIT:
		if (odp_pktio_term_global()) {
			ODP_ERR("ODP pktio term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SCHED_INIT:
		if (sched_fn->term_global()) {
			ODP_ERR("ODP schedule term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (queue_fn->term_global()) {
			ODP_ERR("ODP queue term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (odp_pool_term_global()) {
			ODP_ERR("ODP buffer pool term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		if (odp_thread_term_global()) {
			ODP_ERR("ODP thread term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_global()) {
			ODP_ERR("ODP ishm term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case FDSERVER_INIT:
		if (_odp_fdserver_term_global()) {
			ODP_ERR("ODP fdserver term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SYSINFO_INIT:
		if (odp_system_info_term()) {
			ODP_ERR("ODP system info term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIME_INIT:
		if (odp_time_term_global()) {
			ODP_ERR("ODP time term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CPUMASK_INIT:
		if (odp_cpumask_term_global()) {
			ODP_ERR("ODP cpumask term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NO_INIT:
		;
	}

	return rc;
}

int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type)
{
	enum init_stage stage = NO_INIT;

	if (instance != (odp_instance_t)odp_global_data.main_pid) {
		ODP_ERR("Bad instance.\n");
		goto init_fail;
	}

	if (_odp_ishm_init_local()) {
		ODP_ERR("ODP ishm local init failed.\n");
		goto init_fail;
	}
	stage = ISHM_INIT;

	if (odp_thread_init_local(thr_type)) {
		ODP_ERR("ODP thread local init failed.\n");
		goto init_fail;
	}
	stage = THREAD_INIT;

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		goto init_fail;
	}
	stage = PKTIO_INIT;

	if (odp_pool_init_local()) {
		ODP_ERR("ODP pool local init failed.\n");
		goto init_fail;
	}
	stage = POOL_INIT;

	if (queue_fn->init_local()) {
		ODP_ERR("ODP queue local init failed.\n");
		goto init_fail;
	}
	stage = QUEUE_INIT;

	if (sched_fn->init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		goto init_fail;
	}
	/* stage = SCHED_INIT; */

	return 0;

init_fail:
	_odp_term_local(stage);
	return -1;
}

int odp_term_local(void)
{
	return _odp_term_local(ALL_INIT);
}

int _odp_term_local(enum init_stage stage)
{
	int rc = 0;
	int rc_thd = 0;

	switch (stage) {
	case ALL_INIT:

	case SCHED_INIT:
		if (sched_fn->term_local()) {
			ODP_ERR("ODP schedule local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (queue_fn->term_local()) {
			ODP_ERR("ODP queue local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (odp_pool_term_local()) {
			ODP_ERR("ODP buffer pool local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		rc_thd = odp_thread_term_local();
		if (rc_thd < 0) {
			ODP_ERR("ODP thread local term failed.\n");
			rc = -1;
		} else {
			if (!rc)
				rc = rc_thd;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_local()) {
			ODP_ERR("ODP ishm local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	default:
		break;
	}

	return rc;
}
