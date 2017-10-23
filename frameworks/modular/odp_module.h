/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Modular framework solves the problem of choosing a module
 * from multiple modules of a subsystem.
 *
 * The choice is available during compile time or during runtime
 * or initialization. The runtime choice could be using shared
 * libraries or dynamic loadable libraries.
 *
 * Multiple modules of the same subsystem can be built into
 * individual static libraries(.a), shared libraries(.so) to be
 * dynamically linked or loaded, and use constructor functions
 * to register themselves.
 *
 * A subsystem can choose one active module and provide APIs to
 * switch between modules.
 *
 * Alternatively, subsystem can load multiple modules and
 * determine the APIs route in runtime.
 *
 * In order to gain full possible performance, the subsystem
 * allows for choosing a specific module at compile time.
 * This eliminates the need to choose the module using function
 * pointer table.
 *
 * This framework tries to minimizes dependencies to the linked
 * list and rwlock facilities only.
 */

#ifndef ODP_MODULE_H_
#define ODP_MODULE_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <odp/api/rwlock.h>
#include "list.h"

/* Forward declaration */
typedef struct odp_module_base odp_module_base_t;

/* Subsystem */
typedef struct odp_subsystem {
	odp_rwlock_t lock;
	uint32_t version;
	const char *name;
	const char *description;
	struct list_head modules;
	odp_module_base_t *active;
} odp_subsystem_t;

/* Internally construct subsystem instance name */
#define __subsystem(name) odp_ ## name ## _subsystem

/* Declare an ODP subsystem in header file */
#define ODP_SUBSYSTEM_DECLARE(name) \
	extern odp_subsystem_t __subsystem(name)

/* Define an ODP subsystem in source file */
#define ODP_SUBSYSTEM_DEFINE(_name, _description, _version)	\
	odp_subsystem_t __subsystem(_name) =			\
	{							\
		.lock = ODP_RWLOCK_UNLOCKED,			\
		.name = # _name,				\
		.version = _version,				\
		.description = _description,			\
	}

/* Internally construct subsystem API name */
#define __odp_api(subsystem, api) odp_ ## subsystem ##_## api

/* Subsystem API prototype name */
#define odp_api_proto(subsystem, api) __odp_api(subsystem, api ## _proto_t)

/* Subsystem API declaration */
#define ODP_SUBSYSTEM_API(name, _return, api, ...)		\
	extern _return __odp_api(name, api)(__VA_ARGS__);	\
	typedef _return (*odp_api_proto(name, api))(__VA_ARGS__)

/* Subsystem API stubs are weak */
#define ODP_SUBSYSTEM_API_STUB(name, api)			\
	__attribute__((weak)) __odp_api(name, api)

/* In case a subsystem module are built as static libraries(.a)
 * or preload dynamic libraries(.so), the module can use this
 * macro to override the APIs weak stubs.
 */
#define ODP_SUBSYSTEM_API_OVERRIDE(name, api, _alias)		\
	__attribute__((alias(#_alias))) __odp_api(name, api)

#define odp_subsystem_constructor(name)				\
	do {							\
		odp_rwlock_init(&__subsystem(name).lock);	\
		list_head_init(&__subsystem(name).modules);	\
		__subsystem(name).active = NULL;		\
	} while (0)

#define ODP_SUBSYSTEM_CONSTRUCTOR(name)				\
	static void __attribute__((constructor(101)))		\
		odp_ ## name ## _subsystem_constructor(void)

#define odp_subsystem_lock(access, name)			\
	odp_rwlock_ ## access ## _lock(&__subsystem(name).lock)

#define odp_subsystem_unlock(access, name)			\
	odp_rwlock_ ## access ## _unlock(&__subsystem(name).lock)

/* Base class to all inherited subsystem module classes */
struct odp_module_base {
	struct list_node list;
	const char *name;
	void *handler; /* DSO */
	int (*init_local)(void);
	int (*term_local)(void);
	int (*init_global)(void);
	int (*term_global)(void);
};

/* It is required to define subsystem module class with the
 * base class as its 1st member and named as "base", and also
 * use ODP_MODULE_CLASS(subsystem) to create the association
 * between module class name and subsystem name, like:
 *
 * typedef ODP_MODULE_CLASS(subsystem) {
 *	odp_module_base_t base;
 *	...new members...
 * } new_module_t; // Here pick the name you like freely
 *
 * It also supports forward declaration like:
 *
 * // Forward declaration
 * typedef ODP_MODULE_CLASS(subsystem) new_module_t;
 * // Laterly comes the definition
 * ODP_MODULE_CLASS(subsystem) {
 *	odp_module_base_t base;
 *	...new members...
 * }
 *
 * Then in preprocessor macros when we have the subsystem name
 * we can recover the module class type information, like:
 *
 * #define MACRO(subsystem)
 * do {
 *	ODP_MODULE_CLASS(subsystem) *mod = NULL;
 *	odp_subsystem_foreach_module(subsystem, mod) {
 *		mod->xxx; // access the module class
 *	}
 * } while(0)
 */
#define ODP_MODULE_CLASS(subsystem) struct odp_ ## subsystem ## _module

/* Below macros assume that all subsystem module classes have
 * odp_module_base_t as their 1st member named "base".
 *
 * This greatly reduces the complexity for module list iteration
 * and module pointer recovery from its list_node member by a forced
 * type conversion instead of complex calls to container_of() etc.
 */
#define __force_cast(module, node)				\
	((typeof(module))((void *)(node)))

#define __foreach_module(pos, head)				\
	for (pos = __force_cast(pos, (head)->node.next);	\
	     pos != __force_cast(pos, head);			\
	     pos = __force_cast(pos, (pos)->base.list.next))

#define __foreach_module_safe(pos, n, head)			\
	for (pos = __force_cast(pos, (head)->node.next),	\
	     n = __force_cast(pos, (pos)->base.list.next);	\
	     pos != __force_cast(pos, head);			\
	     pos = n, n = __force_cast(next, (next)->base.list.next))

#define odp_subsystem_active_module(name, mod)			\
	__force_cast(mod, __subsystem(name).active)

#define odp_subsystem_foreach_module(name, mod)			\
	__foreach_module(mod, &__subsystem(name).modules)

#define odp_subsystem_foreach_module_safe(name, mod, next)	\
	__foreach_module_safe(mod, next, &__subsystem(name).modules)

#define odp_module_constructor(mod) list_node_init(&(mod)->base.list)

/* Module constructors should be later than subsystem constructors,
 * in statically linked scenarios (both subsystems and modules are
 * linked statically). thus the priority 102 compared to the above
 * subsystem constructor priority 101.
 */
#define ODP_MODULE_CONSTRUCTOR(name)				\
	static void __attribute__((constructor(102)))		\
		odp_ ## name ## _module_constructor(void)

/* All subsystems' initialization and termination routines are
 * the same, provide template to help generate similar routines
 * automatically, examples:
 *
 * ODP_SUBSYSTEM_FOREACH_TEMPLATE(subsystem, init_global, DBG)
 * will generate a function walk through all the modules of the
 * subsystem and invoke init_global method for each.
 */
#define ODP_SUBSYSTEM_FOREACH_TEMPLATE(subs, method, print)	\
int odp_ ## subs ##_## method(bool continue_on_errors)		\
{								\
	int result = 0;						\
	ODP_MODULE_CLASS(subs) * mod = NULL;			\
								\
	odp_subsystem_lock(read, subs);				\
	odp_subsystem_foreach_module(subs, mod) {		\
		result = mod->base.method ?			\
				mod->base.method() : 0;		\
		if (result < 0) {				\
			print("error %d to %s subsystem %s "	\
			      "module %s.\n", result, #method,	\
			      __subsystem(subs).name,		\
			      mod->base.name);			\
								\
			if (continue_on_errors)			\
				continue;			\
			else					\
				goto done;			\
		}						\
	}							\
done:								\
	odp_subsystem_unlock(read, subs);			\
	return result;						\
}

/* Subsystem Modules Registration
 *
 * odp_subsystem_register_module() are called by all modules in their
 * constructors, whereas the modules could be:
 *
 * 1) built as static libraries(.a) and linked statically, or
 *    built as shared libraries(.so) and linked dynamically.
 *
 *    odp_subsystem_register_module() should complete the whole
 *    registration session and link the module into subsystem's
 *    module array.
 *
 * 2) built as shared libraries(.so) and loaded by a module loader
 *    in runtime with libdl APIs
 *
 *    The whole registration session needs to be split to aim the
 *    module loader to properly handle dlopen() returns, and save
 *    the DSO handler into module's data structure.
 *
 *    The module loader should program in this way:
 *	odp_module_loader_start();
 *	......
 *	for each module
 *		handler = dlopen(module);
 *		// The module constructor runs before dlopen() returns
 *		// which in turn calls odp_subsystem_register_module()
 *		if (handler is valid)
 *			odp_module_install(handler);
 *		else
 *			odp_module_abandon();
 *      ......
 *	odp_module_loader_end();
 */

void odp_module_loader_start(void);
void odp_module_loader_end(void);

int odp_module_install(void *, bool active);
int odp_module_abandon(void);

#define __maybe_unused __attribute__((unused))
static inline void __subsystem_set_active(
	odp_subsystem_t *subsystem __maybe_unused,
		odp_module_base_t *module __maybe_unused)
{
#if defined(IM_ACTIVE_MODULE)
	subsystem->active = module;
#endif
}

int __subsystem_register_module(
	odp_subsystem_t *, odp_module_base_t *);

/* Macro to allow polymorphism on module classes */
#define odp_subsystem_register_module(name, module)		\
({								\
	odp_module_base_t *base = &(module)->base;		\
	__subsystem_register_module(&__subsystem(name), base);	\
	__subsystem_set_active(&__subsystem(name), base);	\
})

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif
