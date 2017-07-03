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
 * Modular programming framework supports runtime selectable
 * implementations for variant software subsystems.
 *
 * Multiple implementations of the same subsystem can be built
 * into individual static libraries or loadable DSOs, and use
 * constructor functions to register themselves.
 *
 * A subsystem can choose one active implementation and provide
 * APIs to switch between implementations.
 *
 * Alternatively, subsystem can load multiple implementations
 * and determine the APIs route in runtime.

 * Also in need to pursue extreme performance the subsystem
 * can choose one specific implementation module and build it
 * to override subsystem API symbols directly, thus eliminate
 * one level indirection of API calls through function pointers.
 *
 * This framework tries to minimizes dependencies to the linked
 * list and rwlock facilities only.
 */

#ifndef MODULE_H
#define MODULE_H

#include <stdbool.h>
#include <odp/api/rwlock.h>
#include "list.h"

typedef struct {
	odp_rwlock_t lock;
	uint32_t version;
	const char *name;
	const char *description;
	struct list_head modules;
	struct list_node *active;
} subsystem_t;

/* Subsystem instance name */
#define subsystem(name) name ## _subsystem

/* The trick is to use macro SUBSYSTEM() for both subsystem
 * declaration and definition. ARGC() macro chooses either
 * SUBSYSTEM_DEFINE() or SUBSYSTEM_DECLARE() depends on argument
 * number,
 */
#define _ARGC(_0, _1, _2, _3, ...) _3
#define  ARGC(...) _ARGC(__VA_ARGS__, DEFINE, 2, DECLARE, 0)

#define _OVERLOAD(M, S, ...) M ## _ ## S(__VA_ARGS__)
#define  OVERLOAD(M, S, ...) _OVERLOAD(M, S, __VA_ARGS__)

#define SUBSYSTEM_DEFINE(_name, _description, _version)		\
	subsystem_t subsystem(_name) = {			\
		.lock = ODP_RW_LOCK_UNLOCK(lock),		\
		.name = # _name,				\
		.version = _version,				\
		.description = _description,			\
	}

#define SUBSYSTEM_DECLARE(name) subsystem_t subsystem(name)
#define SUBSYSTEM(...) OVERLOAD(SUBSYSTEM, ARGC(__VA_ARGS__), __VA_ARGS__)

/* Subsystem API prototype name */
#define api_proto(subsystem, api) subsystem ##_## api ## _proto_t

/* Subsystem API declaration */
#define SUBSYSTEM_API(name, _return, api, ...) 			\
	extern _return name ##_## api(__VA_ARGS__);		\
	typedef _return (*api_proto(name, api))(__VA_ARGS__)	\

/* Subsystem API stubs are weak */
#define SUBSYSTEM_API_STUB(name, api) 				\
	__attribute__((weak)) name ##_## api

/* In case subsystem API implementations are built as static
 * libraries or preload DSOs, one implementation can use this
 * macro to override the APIs weak stubs.
 */
#define SUBSYSTEM_API_OVERRIDE(name, api, _alias)		\
	__attribute__((alias(#_alias))) name ##_## api

#define subsystem_constructor(name) 				\
	do {							\
		odp_rwlock_init(&subsystem(name).lock);		\
		list_head_init(&subsystem(name).modules);	\
		subsystem(name).active = NULL;			\
	} while(0)

#define SUBSYSTEM_CONSTRUCTOR(name) 				\
	static void __attribute__((constructor(101)))		\
		name ## _subsystem_constructor(void)

#define subsystem_lock(access, name)				\
	odp_rwlock_ ##access## _lock(&subsystem(name).lock)

#define subsystem_unlock(access, name)				\
	odp_rwlock_ ##access## _unlock(&subsystem(name).lock)

/* Below macros assume that all module classes derive from
 * module_base_t class by using MODULE_CLASS macro in their
 * typedefs and have list_node as their 1st member named "list".
 *
 * This greatly reduces the complexity for subsystem's module
 * list iteration and module pointer recovery from its list_node
 * member by a forced type conversion intead of complex calls to
 * container_of() etc.
 */
#define __force_cast(module, node)				\
	((typeof(module)) ((void *)(node)))

#define subsystem_active_module(name, mod)			\
	__force_cast(mod, subsystem(name).active)

#define __foreach_module(pos, head)				\
	for (pos = __force_cast(pos, (head)->node.next);	\
	     pos != __force_cast(pos, head);			\
	     pos = __force_cast(pos, (pos)->list.next))

#define __foreach_module_safe(pos, n, head)			\
	for (pos = __force_cast(pos, (head)->node.next),	\
	     n = __force_cast(pos, (pos)->list.next);		\
	     pos != __force_cast(pos, head);			\
	     pos = n, n = __force_cast(next, (next)->list.next))

#define subsystem_foreach_module(name, mod)			\
	__foreach_module(mod, &subsystem(name).modules)

#define subsystem_foreach_module_safe(name, mod, next)		\
	__foreach_module_safe(mod, next, &subsystem(name).modules)

#define MODULE_CLASS(subsystem)					\
	struct subsystem ## _module {				\
		struct list_node list;				\
		const char *name;				\
		void *handler; /* DSO */			\
		int (*init_local)(void);			\
		int (*term_local)(void);			\
		int (*init_global)(void);			\
		int (*term_global)(void);			\

/* Base class to all inherited subsystem module classes */
typedef MODULE_CLASS(base) } module_base_t;

#define module_constructor(mod) 				\
	do { list_node_init(&(mod)->list); } while(0)

/* Module constructors should be late than subsystem constructors,
 * in statically linked scenarios (both subsystems and modules are
 * linked statically). thus the priority 102 compared to the above
 * subsystem constructor priority 101.
 */
#define MODULE_CONSTRUCTOR(name) 				\
	static void __attribute__((constructor(102)))		\
		name ## _module_constructor(void)

/* All subsystems' initialization and termination routines are
 * the same, provide template to instantiation.
 */
#define SUBSYSTEM_INITERM_TEMPLATE(subs, method, print)		\
static inline int subs ## _subsystem ##_## method(void)		\
{								\
	module_base_t *mod = NULL;				\
								\
	subsystem_lock(read, subs);				\
	subsystem_foreach_module(subs, mod) {			\
		int result = mod->method ? mod->method() : -1;	\
		if (result < 0) {				\
			subsystem_unlock(read, subs);		\
			print("error %d to %s subsystem %s "	\
			      "module %s.\n", result, # method, \
			      subsystem(subs).name, mod->name);	\
			return result;				\
		}						\
	}							\
	subsystem_unlock(read, subs);				\
	return 0;						\
}

/* Subsystem Modules Registration
 *
 * subsystem_register_module() are called by all modules in their
 * constructors, whereas the modules could be:
 *
 * 1) Linked statically or dynamically, and are loaded by program
 *    loader (execve) or dynamic linker/loader (ld.so)
 *
 *    subsystem_register_module() should complete the whole
 *    registration session and link the module into subsystem's
 *    module array.
 *
 * 2) Loaded by a module loader in runtime with libdl APIs
 *
 *    The whole registration session needs to be split to aim the
 *    module loader to properly handle dlopen() returns, and save
 *    the DSO handler into module's data structure.
 *
 *    The module loader should program in this way:
 *	module_loader_start();
 *	......
 * 	for each module
 *		handler = dlopen(module)
 *		-- the module constructor calls register_module()
 *		if (handler is valid)
 *			install_dso(handler);
 *		else
	 		abandon_dso();
 *      ......
 *	module_loader_end();
 */

extern void module_loader_start(void);
extern void module_loader_end(void);

extern int module_install_dso(void *, bool active);
extern int module_abandon_dso(void);

#define __maybe_unused __attribute__((unused))
static inline void __subsystem_set_active(
	subsystem_t *subsystem __maybe_unused,
		module_base_t *module __maybe_unused)
{
#if defined(IM_ACTIVE_MODULE)
	subsystem->active = &module->list;
#endif
}

extern int __subsystem_register_module(
		subsystem_t *, module_base_t *);

/* Macro to allow polymorphism on module classes */
#define subsystem_register_module(name, module)			\
({								\
	module_base_t *base = (module_base_t *)module;		\
	__subsystem_register_module(&subsystem(name), base);	\
	__subsystem_set_active(&subsystem(name), base);		\
})

#endif
