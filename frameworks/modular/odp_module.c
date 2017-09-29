/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <config.h>

#include <stdio.h>
#include <errno.h>
#include "odp_module.h"

#define MODULE_FRAMEWORK_VERSION 0x00010000UL
ODP_SUBSYSTEM_DEFINE(module, "module framework", MODULE_FRAMEWORK_VERSION);

/* Bootstrap log facility, enable if ODP_DEBUG_PRINT flag is set. */
#define DBG(format, ...)					\
	do {							\
		if (ODP_DEBUG_PRINT == 1)			\
			fprintf(stderr, format, ##__VA_ARGS__);	\
	} while (0)

/* Keep it simple, allow one registration session at a time. */
static struct {
	odp_rwlock_t lock;
	odp_subsystem_t *subsystem;
	odp_module_base_t *module;
} registration = {
	.lock = ODP_RWLOCK_UNLOCKED,
	.subsystem = NULL,
	.module = NULL,
};

static inline int registration_sanity_check(
	odp_subsystem_t *subsystem, odp_module_base_t *module)
{
	if (subsystem == NULL || module == NULL)
		return -ENOENT;

	if (!list_node_detached(&module->list)) {
		DBG("module %s was already registered.\n", module->name);
		return -EAGAIN;
	}

	return 0;
}

/* Module is linked statically or dynamically, and are loaded by
 * program loader (execve) or dynamic linker/loader (ld.so)
 *
 * subsystem_register_module() should complete the whole registration
 * session and link the module into subsystem's module array.
 */
static int linker_register_module(
	odp_subsystem_t *subsystem, odp_module_base_t *module)
{
	int sanity = registration_sanity_check(subsystem, module);

	if (sanity < 0) /* sanity check errors */
		return sanity;

	/* Allow one registration session at a time */
	odp_rwlock_write_lock(&registration.lock);

	/* Block the subsystem API calls in load new
	 * implementation modules. */
	odp_rwlock_write_lock(&subsystem->lock);
	module->handler = NULL; /* no DSO handler */
	list_add_tail(&subsystem->modules, &module->list);
	odp_rwlock_write_unlock(&subsystem->lock);

	odp_rwlock_write_unlock(&registration.lock);
	return 0;
}

static int (*do_register_module)(odp_subsystem_t *, odp_module_base_t *)
		= &linker_register_module;

static int loader_register_module(
	odp_subsystem_t *subsystem, odp_module_base_t *module)
{
	int sanity = registration_sanity_check(subsystem, module);

	if (sanity < 0) /* sanity check errors */
		return sanity;

	/* Registration session lock must be held by
	 * module_loader_start(). */
	if (odp_rwlock_write_trylock(&registration.lock) == 0) {
		registration.subsystem = subsystem;
		registration.module = module;
		return 0;
	}

	odp_rwlock_write_unlock(&registration.lock);
	return -EACCES;
}

void odp_module_loader_start(void)
{
	odp_rwlock_write_lock(&registration.lock);

	if (registration.module != NULL ||
	    registration.subsystem != NULL) {
		DBG("module loader start warn, A previous "
		    "registration did not complete yet.\n");
	}

	registration.module = NULL;
	registration.subsystem = NULL;
	do_register_module = &loader_register_module;
}

void odp_module_loader_end(void)
{
	if (registration.module != NULL ||
	    registration.subsystem != NULL) {
		DBG("module loader end warn, A previous "
		    "registration did not complete yet.\n");
	}

	registration.module = NULL;
	registration.subsystem = NULL;
	do_register_module = &linker_register_module;

	odp_rwlock_write_unlock(&registration.lock);
}

int odp_module_install(void *dso, bool active)
{
	/* Bottom halves of the registration, context exclusion
	 * is guaranteed by module_loader_start()
	 */
	if (odp_rwlock_write_trylock(&registration.lock) == 0) {
		odp_subsystem_t *subsystem = registration.subsystem;
		odp_module_base_t *module = registration.module;

		if (subsystem != NULL && module != NULL) {
			odp_rwlock_write_lock(&subsystem->lock);

			module->handler = dso;
			list_add_tail(&subsystem->modules, &module->list);

			/* install as active implementation */
			if (active) /* warn: replaceable */
				subsystem->active = module;

			odp_rwlock_write_unlock(&subsystem->lock);
		}

		registration.subsystem = NULL;
		registration.module = NULL;
		return 0;
	}

	odp_rwlock_write_unlock(&registration.lock);
	return -EACCES;
}

int odp_module_abandon(void)
{
	/* Bottom halves of the registration, context exclusion
	 * is guaranteed by module_loader_start()
	 */
	if (odp_rwlock_write_trylock(&registration.lock) == 0) {
		registration.subsystem = NULL;
		registration.module = NULL;
		return 0;
	}

	odp_rwlock_write_unlock(&registration.lock);
	return -EACCES;
}

int __subsystem_register_module(
	odp_subsystem_t *subsystem, odp_module_base_t *module)
{
	return do_register_module(subsystem, module);
}
