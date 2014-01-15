/* Copyright (c) 2013, Linaro Limited
 * All rights reserved
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * The OpenDataPlane API
 *
 */

/**
 * @mainpage
 *
 * @section sec_1 Introduction
 *
 * OpenDataPlane (ODP) provides a data plane application programming
 * environment that is easy to use, high performance, and portable
 * between networking SoCs. This documentation is both a user guide
 * for developers who wish to use ODP and a detailed reference for ODP
 * programmers covering APIs, data structures, files, etc.  It should
 * also be useful for those wishing to implement ODP on other
 * platforms.
 *
 *  @image html overview.png
 *  @image latex overview.eps "overview" width=\textwidth
 *
 * ODP consists of a common layer and an implementation layer.
 * Applications written to the common layer are portable across all
 * ODP implementations.  To compile and run an ODP application, it is
 * compiled against a specific ODP implementation layer.  The purpose
 * of the implementation layer is to provide an optimal mapping of ODP
 * APIs to the underlying capabilities (including hardware
 * co-processing and acceleration support) of of SoCs hosting ODP
 * implementations.  As a bootstrapping mechanism for applications, as
 * well as to provide a model for ODP implementers, ODP provides a
 * 'linux-generic' reference implementation designed to run on any SoC
 * which has a Linux kernel.  While linux-generic is not a performance
 * target, it does provide a starting point for ODP implementers and
 * application programmers alike.  As a pure software implementation
 * of ODP, linux-generic is designed to provide best-in-class performance
 * for general Linux data plane support.
 *
 * @section Staging
 *
 * ODP is a work in progress and is expected to evolve significantly
 * as it develops.  Since the goal of ODP is to provide portability
 * across disparate platforms and architectures while still providing
 * near-native levels of performance on each conforming
 * implementation, it is expected that the ODP architecture and the
 * APIs presented here will evolve based on the experience in
 * implementing and tuning ODP for operation on multiple platforms.
 * For the time being, then, the goal here is not so much as to
 * present a stable API, but rather a usable one that can be built
 * upon to reach a clearly defined end goal.
 *
 * ODP releases will follow a standard major/minor/revision
 * three-level naming designation.  The intent is that APIs will be
 * stable across major revisions such that existing APIs will work
 * unchanged within a major revision, though minor revisions may add
 * new APIs.  Across major revisions some API changes may make
 * application source changes necesary.  These will be clearly noted
 * in the release notes associated with any given ODP release.
 *
 * This consistency will commence with the 1.0.0 release of ODP, which
 * is expected later in 2014.  Pre-release 1 it should be expected
 * that minor revisions may require API source changes as ODP is still
 * "growing its roots".  This is release 0.1.0 of ODP and is being
 * made available as a "public preview" to the open source community
 * for comment/feedback/evaluation.
 *
 * @section contact Contact Details
 * - The main web site is http://www.opendataplane.org/
 * - The git repo is https://git.linaro.org/lng/odp.git
 * - Bug tracking https://launchpad.net/linaro-odp
 *
 *
 * @section sec_2 User guide
 *
 * @subsection sub2_1 The ODP API
 *
 * This file (odp.h) is the main ODP API file. User should include only this
 * file to keep portability since structure and naming of sub header files
 * may be change between implementations.
 *
 * @subsection sub2_2 Threading
 *
 * ODP does not specify a threading model.  Applications can use
 * processes or pthreads, or Roll-Your-Own (RYO) threading/fibre
 * mechanisms for multi-threading as needed. Creation and control of
 * threads is the responsibility of the ODP application. For optimal
 * performance on many-core SoCs, it is recommended that threads be
 * run on dedicated cores. ODP provides high-level APIs for core
 * enumeration and assignment while the corresponding ODP
 * implementation layer provides the appropriate mechanisms to realize
 * these functions.
 *
 * Threads used for ODP processing should be pinned into separate cores.
 * Commonly these threads process packets in a run-to-completion loop.
 * Application should avoid blocking threads used for ODP processing,
 * since it may cause blocking on other threads/cores.
 *
 * @subsection sub2_3 ODP initialisation
 *
 * Before calling any other ODP API functions, ODP library must be
 * initialised by calling odp_init_global() once and odp_init_local()
 * on each of the cores sharing the same ODP environment (instance).
 *
 * @subsection sub2_4 API Categories
 *
 * APIs provided by ODP cover the following areas:
 *
 * @subsubsection  memory_management Memory Management
 *
 *   This includes macros and other APIs to control memory alignments
 *   of data structures as well as allocation/deallocation services
 *   for ODP-managed objects.  Note that ODP does not wrapper malloc()
 *   or similar platform specific APIs for the sake of wrappering.
 *
 * @subsubsection buffer_management Buffer Management
 *
 *   This includes APIs for defining and managing buffer pools used
 *   for packets and other bulk purposes.  Note that the allocation
 *   and release of buffers from buffer pools is not something done
 *   explicitly by ODP applications, but rather by APIs that use these
 *   buffers.  This is because in most SoCs, actual buffer allocation
 *   and release is accelerated and performed by hardware.  Software's
 *   role in buffer management is normally reserved to allocating
 *   large chunks of memory which are then given to hardware for
 *   automatic management as pools of buffers.  In this way the ODP
 *   application operates independent of how buffers are managed by
 *   the underlying ODP implementation.
 *
 * @subsubsection packet_management Packet Management
 *
 *   This includes APIs and accessor functions for packet descriptors
 *   as well as packet receipt and transmission.
 *
 * @subsubsection syncronisation Synchronization
 *
 *   This includes APIs and related functions for synchronization
 *   involving other ODP APIs, such as barriers and related atomics.
 *   Again, as ODP does not specify a threading model applications
 *   make use whatever synchronization primitives are native to the
 *   model they use.
 *
 * @subsubsection core_enumeration Core Enumeration and managment
 *
 *   This includes APIs to allow applications to enumerate and
 *   reference cores and per-core data structures.
 *
 * @subsection sub2_5 Miscellaneous Facilities
 *
 * ODP includes miscellaneous facilities for compiler hints and
 * optimizations common in GCC.  [Not sure if we want to consider
 * these an "API" per se].
 *
 * @subsection sub2_6 Application Programming Model
 *
 * ODP supports applications that execute using a "run to completion"
 * programming model.  This means that once dispatched, application
 * threads are not interrupted by the kernel or other scheduling
 * entity.
 *
 * Application threads receive work requests as \a events that are
 * delivered on application and/or implementation defined
 * \a queues.  ODP application code would thus normally be
 * structured as follows:
 *
 * ~~~{.c}
 * #include <odp.h>
 * ...other needed #includes
 *
 * int main (int argc, char *argv[])
 * {
 *         ...application-specific initialization
 *         odp_init_global();
 *
 *         ...launch threads
 *         ...wait for threads to terminate
 * }
 *
 * void worker_thread (parameters)
 * {
 *         odp_init_local();
 *
 *         while (1) {
 *             do_work(get_work());  // Replace with ODP calls when defined
 *         }
 *
 * }
 * ~~~
 *
 * Events are receved on input queues and are processed until they are
 * placed on an output queue of some sort.  The thread then gets the
 * next event to be processed from an input queue and repeats the
 * process.
 *
 * @subsection sub3_1 Asynchronous Operations
 *
 * Note that work to be performed by a thread may require access to an
 * asynchronous function that takes a significant amount of time to
 * complete.  In such cases the event is forwarded to another worker
 * thread or hardware accelerator, depending on the implementation, by
 * placing it on anothert queue, which is an output queue of the
 * thread making the request. This event in turn is received and
 * processed by the thread/accelerator that handles it via its input
 * queue.  When this aysynchronous event is complete, the event is
 * placed on the handler's output queue, which feeds back to the
 * original requestor's input queue.  When the requesting thread next
 * receives this event it resumes processing of the event following
 * the asynchronous event and works on it either until it is ready for
 * final disposition, or until another asynchronous operation is
 * required to process the event.
 *
 * @subsection sub3_2 Queue Linkages
 *
 * The mapping of input and output queues that connect worker threads
 * to accelerators and related offload functions is a cooperation
 * between the implementation and the ODP application.  The
 * implementation defines the service funtions that are available to
 * worker threads (e.g., cypto offload services) and as part of that
 * definition defines the queue structure that connects requests to
 * those services as well as the outputs from those services that
 * connect back to the requesting workers.  The ODP application, in
 * turn, defines the number of worker threads and how they cooperate
 * among themselves.  Note that the application may use ODP core
 * enumeration APIs to decide how many such worker threads should be
 * deployed.
 *
 * @subsection sub3_3 Packet I/O
 *
 * In ODP packet I/O is implicit by reading from and writing to queues
 * associated with interfaces.  An ODP application receives packets by
 * dequeuing an event from an input queue associated with an I/O
 * interface.  This either triggers a packet read or (more likely)
 * simply provides the next (queued) packet from the associated
 * interface.  The actual mechanism used to effect the receipt of the
 * packet is left to the ODP implementation and may involve any
 * combination of sofware and/or hardware operations.
 *
 * Similarly, packet transmission is performed by writing a packet to
 * an output queue associated with an I/O interface.  Again, this
 * schedules the packet for output using some combination of software
 * and/or hardware as determined by the implementation.  ODP applications
 * themselves, therefore, are freed from the details of how packet I/O
 * is performed or buffered to minimize latencies.  The latter is the
 * concern of the ODP implementation to achieve optimal results for
 * the platform supporting the implementation.
 *
 * @subsection How to Use this Reference
 *
 * This reference provides an overview of each data structure and API
 * function, along with a graphical representation of the various
 * structural dependencies among them.  When using the HTML version of
 * this reference, all links are dynamic and provide access to the
 * underlying implementation source files as well, thus providing both
 * a ready reference to API parameters and syntax, as well as
 * convenient access to the actual implementation behind them to
 * further programmer understandng.
 */

#ifndef ODP_H_
#define ODP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_config.h>

#include <odp_version.h>
#include <odp_std_types.h>

#include <odp_align.h>
#include <odp_hints.h>
#include <odp_debug.h>
#include <odp_byteorder.h>
#include <odp_coremask.h>
#include <odp_barrier.h>
#include <odp_spinlock.h>
#include <odp_atomic.h>

#include <odp_init.h>
#include <odp_system_info.h>
#include <odp_thread.h>
#include <odp_shared_memory.h>
#include <odp_buffer.h>
#include <odp_buffer_pool.h>
#include <odp_queue.h>
#include <odp_ticketlock.h>
#include <odp_time.h>
#include <odp_schedule.h>
#include <odp_sync.h>
#include <odp_packet.h>
#include <odp_packet_io.h>

#ifdef __cplusplus
}
#endif
#endif
