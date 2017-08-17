include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

lib_LTLIBRARIES = $(LIB)/libodp-dpdk.la

PLAT_CFLAGS  =
if ARCH_IS_X86
PLAT_CFLAGS  += -msse4.2
endif

if DPDK_DEFAULT_DIR
PLAT_CFLAGS += -include /usr/include/dpdk/rte_config.h
else
PLAT_CFLAGS += -include $(SDK_INSTALL_PATH)/include/rte_config.h
endif

AM_CFLAGS +=  $(PLAT_CFLAGS)
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/frameworks/modular
AM_CFLAGS +=  -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_builddir)/include
AM_CFLAGS +=  -Iinclude
AM_CFLAGS +=  -DSYSCONFDIR=\"@sysconfdir@\"
AM_CFLAGS +=  -D_ODP_PKTIO_IPC

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(LIBCONFIG_CFLAGS)

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_api.h \
		  $(top_srcdir)/include/odp_drv.h

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(srcdir)/include/odp/visibility_begin.h \
		  $(srcdir)/include/odp/visibility_end.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(srcdir)/include/odp/api/align.h \
		  $(srcdir)/include/odp/api/atomic.h \
		  $(srcdir)/include/odp/api/barrier.h \
		  $(srcdir)/include/odp/api/buffer.h \
		  $(srcdir)/include/odp/api/byteorder.h \
		  $(srcdir)/include/odp/api/classification.h \
		  $(srcdir)/include/odp/api/compiler.h \
		  $(srcdir)/include/odp/api/cpu.h \
		  $(srcdir)/include/odp/api/cpumask.h \
		  $(srcdir)/include/odp/api/crypto.h \
		  $(srcdir)/include/odp/api/debug.h \
		  $(srcdir)/include/odp/api/deprecated.h \
		  $(srcdir)/include/odp/api/errno.h \
		  $(srcdir)/include/odp/api/event.h \
		  $(srcdir)/include/odp/api/feature.h \
		  $(srcdir)/include/odp/api/hash.h \
		  $(srcdir)/include/odp/api/hints.h \
		  $(srcdir)/include/odp/api/init.h \
		  $(srcdir)/include/odp/api/ipsec.h \
		  $(srcdir)/include/odp/api/packet_flags.h \
		  $(srcdir)/include/odp/api/packet.h \
		  $(srcdir)/include/odp/api/packet_io.h \
		  $(srcdir)/include/odp/api/packet_io_stats.h \
		  $(srcdir)/include/odp/api/pool.h \
		  $(srcdir)/include/odp/api/queue.h \
		  $(srcdir)/include/odp/api/random.h \
		  $(srcdir)/include/odp/api/rwlock.h \
		  $(srcdir)/include/odp/api/rwlock_recursive.h \
		  $(srcdir)/include/odp/api/schedule.h \
		  $(srcdir)/include/odp/api/schedule_types.h \
		  $(srcdir)/include/odp/api/shared_memory.h \
		  $(srcdir)/include/odp/api/spinlock.h \
		  $(srcdir)/include/odp/api/spinlock_recursive.h \
		  $(srcdir)/include/odp/api/std_clib.h \
		  $(srcdir)/include/odp/api/std_types.h \
		  $(srcdir)/include/odp/api/support.h \
		  $(srcdir)/include/odp/api/sync.h \
		  $(srcdir)/include/odp/api/system_info.h \
		  $(srcdir)/include/odp/api/thread.h \
		  $(srcdir)/include/odp/api/thrmask.h \
		  $(srcdir)/include/odp/api/ticketlock.h \
		  $(srcdir)/include/odp/api/time.h \
		  $(srcdir)/include/odp/api/timer.h \
		  $(srcdir)/include/odp/api/traffic_mngr.h \
		  $(srcdir)/include/odp/api/version.h

if ARCH_IS_ARM
odpapiinclude_HEADERS += $(srcdir)/arch/arm/odp/api/cpu_arch.h
endif
if ARCH_IS_MIPS64
odpapiinclude_HEADERS += $(srcdir)/arch/mips64/odp/api/cpu_arch.h
endif
if ARCH_IS_POWERPC
odpapiinclude_HEADERS += $(srcdir)/arch/powerpc/odp/api/cpu_arch.h
endif
if ARCH_IS_X86
odpapiinclude_HEADERS += $(srcdir)/arch/x86/odp/api/cpu_arch.h
endif

odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  $(builddir)/include/odp/api/plat/static_inline.h \
		  $(srcdir)/include/odp/api/plat/atomic_inlines.h \
		  $(srcdir)/include/odp/api/plat/atomic_types.h \
		  $(srcdir)/include/odp/api/plat/barrier_types.h \
		  $(srcdir)/include/odp/api/plat/buffer_types.h \
		  $(srcdir)/include/odp/api/plat/byteorder_inlines.h \
		  $(srcdir)/include/odp/api/plat/byteorder_types.h \
		  $(srcdir)/include/odp/api/plat/classification_types.h \
		  $(srcdir)/include/odp/api/plat/cpumask_types.h \
		  $(srcdir)/include/odp/api/plat/crypto_types.h \
		  $(srcdir)/include/odp/api/plat/event_types.h \
		  $(srcdir)/include/odp/api/plat/init_types.h \
		  $(srcdir)/include/odp/api/plat/ipsec_types.h \
		  $(srcdir)/include/odp/api/plat/packet_flag_inlines.h \
		  $(srcdir)/include/odp/api/plat/packet_flag_inlines_api.h \
		  $(srcdir)/include/odp/api/plat/packet_inlines.h \
		  $(srcdir)/include/odp/api/plat/packet_inlines_api.h \
		  $(srcdir)/include/odp/api/plat/packet_io_types.h \
		  $(srcdir)/include/odp/api/plat/packet_types.h \
		  $(srcdir)/include/odp/api/plat/pool_types.h \
		  $(srcdir)/include/odp/api/plat/queue_types.h \
		  $(srcdir)/include/odp/api/plat/rwlock_types.h \
		  $(srcdir)/include/odp/api/plat/rwlock_recursive_types.h \
		  $(srcdir)/include/odp/api/plat/schedule_types.h \
		  $(srcdir)/include/odp/api/plat/shared_memory_types.h \
		  $(srcdir)/include/odp/api/plat/spinlock_types.h \
		  $(srcdir)/include/odp/api/plat/spinlock_recursive_types.h \
		  $(srcdir)/include/odp/api/plat/std_clib_inlines.h \
		  $(srcdir)/include/odp/api/plat/strong_types.h \
		  $(srcdir)/include/odp/api/plat/sync_inlines.h \
		  $(srcdir)/include/odp/api/plat/thread_types.h \
		  $(srcdir)/include/odp/api/plat/thrmask_types.h \
		  $(srcdir)/include/odp/api/plat/ticketlock_inlines.h \
		  $(srcdir)/include/odp/api/plat/ticketlock_inlines_api.h \
		  $(srcdir)/include/odp/api/plat/ticketlock_types.h \
		  $(srcdir)/include/odp/api/plat/time_types.h \
		  $(srcdir)/include/odp/api/plat/timer_types.h \
		  $(srcdir)/include/odp/api/plat/traffic_mngr_types.h \
		  $(srcdir)/include/odp/api/plat/version_types.h

odpdrvincludedir = $(includedir)/odp/drv
odpdrvinclude_HEADERS = \
		  $(srcdir)/include/odp/drv/align.h \
		  $(srcdir)/include/odp/drv/atomic.h \
		  $(srcdir)/include/odp/drv/barrier.h \
		  $(srcdir)/include/odp/drv/byteorder.h \
		  $(srcdir)/include/odp/drv/compiler.h \
		  $(srcdir)/include/odp/drv/driver.h \
		  $(srcdir)/include/odp/drv/hints.h \
		  $(srcdir)/include/odp/drv/shm.h \
		  $(srcdir)/include/odp/drv/spinlock.h \
		  $(srcdir)/include/odp/drv/std_types.h \
		  $(srcdir)/include/odp/drv/sync.h

odpdrvplatincludedir = $(includedir)/odp/drv/plat
odpdrvplatinclude_HEADERS = \
		  $(srcdir)/include/odp/drv/plat/atomic_types.h \
		  $(srcdir)/include/odp/drv/plat/barrier_types.h \
		  $(srcdir)/include/odp/drv/plat/byteorder_types.h \
		  $(srcdir)/include/odp/drv/compiler.h \
		  $(srcdir)/include/odp/drv/plat/driver_types.h \
		  $(srcdir)/include/odp/drv/plat/shm_types.h \
		  $(srcdir)/include/odp/drv/plat/spinlock_types.h \
		  $(srcdir)/include/odp/drv/plat/strong_types.h


noinst_HEADERS = \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_subsystem.h \
		  ${top_srcdir}/platform/linux-generic/include/_fdserver_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/_ishm_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/_ishmphy_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/_ishmpool_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/drv_driver_internal.h\
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  ${srcdir}/include/odp_buffer_inlines.h \
		  ${srcdir}/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_bitmap_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_config_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_forward_typedefs_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${srcdir}/include/odp_packet_dpdk.h \
		  ${srcdir}/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pktio_ops_subsystem.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pktio_ops_loopback.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_name_table_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${srcdir}/include/odp_errno_define.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ipc_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pkt_queue_internal.h \
		  ${srcdir}/include/odp_pool_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pool_subsystem.h \
		  ${srcdir}/include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_subsystem.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_subsystem.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_sorted_list_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_shm_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_time_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_wheel_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_traffic_mngr_internal.h \
		  ${srcdir}/include/protocols/eth.h \
		  ${srcdir}/include/protocols/ip.h \
		  ${srcdir}/include/protocols/ipsec.h \
		  ${srcdir}/include/protocols/tcp.h \
		  ${srcdir}/include/protocols/udp.h \
		  ${srcdir}/Makefile.inc

__LIB__libodp_dpdk_la_SOURCES = \
			   ../linux-generic/_fdserver.c \
			   ../linux-generic/_ishm.c \
			   ../linux-generic/_ishmphy.c \
			   ../linux-generic/_ishmpool.c \
			   ../linux-generic/_modules.c \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_barrier.c \
			   ../linux-generic/odp_bitmap.c \
			   buffer/dpdk.c \
			   ../linux-generic/odp_byteorder.c \
			   ../linux-generic/odp_classification.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   ../linux-generic/odp_cpumask_task.c \
			   odp_crypto.c \
			   odp_errno.c \
			   ../linux-generic/odp_event.c \
			   ../linux-generic/odp_hash.c \
			   odp_init.c \
			   ../linux-generic/odp_impl.c \
			   ../linux-generic/odp_ipsec.c \
			   ../linux-generic/odp_name_table.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   pktio/subsystem.c \
			   odp_packet_flags.c \
			   ../linux-generic/odp_packet_io.c \
			   ../linux-generic/pktio/loopback.c \
			   ../linux-generic/odp_pkt_queue.c \
			   pool/dpdk.c \
			   ../linux-generic/odp_queue_if.c \
			   ../linux-generic/queue/subsystem.c \
			   ../linux-generic/queue/generic.c \
			   ../linux-generic/queue/scalable.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   ../linux-generic/pool/subsystem.c \
			   ../linux-generic/buffer/subsystem.c \
			   ../linux-generic/odp_schedule_if.c \
			   ../linux-generic/schedule/generic.c \
			   ../linux-generic/schedule/iquery.c \
			   ../linux-generic/schedule/scalable.c \
			   ../linux-generic/schedule/scalable_ordered.c \
			   ../linux-generic/schedule/sp.c \
			   ../linux-generic/schedule/subsystem.c \
			   ../linux-generic/odp_shared_memory.c \
			   ../linux-generic/odp_sorted_list.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_spinlock_recursive.c \
			   odp_std_clib.c \
			   ../linux-generic/odp_sync.c \
			   ../linux-generic/odp_system_info.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   odp_time.c \
			   ../linux-generic/odp_timer.c \
			   ../linux-generic/odp_timer_wheel.c \
			   ../linux-generic/odp_traffic_mngr.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   ../linux-generic/drv_atomic.c \
			   ../linux-generic/drv_barrier.c \
			   ../linux-generic/drv_driver.c \
			   ../linux-generic/drv_shm.c \
			   ../linux-generic/drv_spinlock.c

if ARCH_IS_ARM
__LIB__libodp_dpdk_la_SOURCES += arch/arm/odp_cpu_arch.c \
				 arch/arm/odp_sysinfo_parse.c
endif
if ARCH_IS_MIPS64
__LIB__libodp_dpdk_la_SOURCES += arch/mips64/odp_cpu_arch.c \
				 arch/mips64/odp_sysinfo_parse.c
endif
if ARCH_IS_POWERPC
__LIB__libodp_dpdk_la_SOURCES += arch/powerpc/odp_cpu_arch.c \
				 arch/powerpc/odp_sysinfo_parse.c
endif
if ARCH_IS_X86
__LIB__libodp_dpdk_la_SOURCES += arch/x86/cpu_flags.c \
				 arch/x86/odp_cpu_arch.c \
				 arch/x86/odp_sysinfo_parse.c
endif

pool/dpdk.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
buffer/dpdk.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
if ODP_SCHEDULE_SCALABLE
../linux-generic/schedule/scalable.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
if ODP_SCHEDULE_SP
../linux-generic/schedule/sp.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
if ODP_SCHEDULE_IQUERY
../linux-generic/schedule/iquery.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
../linux-generic/schedule/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif
endif
endif
if ODP_SCHEDULE_SCALABLE
../linux-generic/queue/scalable.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
../linux-generic/queue/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif

# Build modular framework into odp-linux library
modularframeworkdir = $(top_srcdir)/frameworks/modular
noinst_HEADERS += $(modularframeworkdir)/list.h \
		  $(modularframeworkdir)/odp_module.h

__LIB__libodp_dpdk_la_SOURCES += ../../frameworks/modular/odp_module.c

__LIB__libodp_dpdk_la_LIBADD = $(ATOMIC_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(DPDK_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(TIMER_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(LIBCONFIG_LIBS)

# Create symlink for ABI header files. Application does not need to use the arch
# specific include path for installed files.
install-data-hook:
	if [ -h $(DESTDIR)$(prefix)/include/odp/api/abi ]; then \
		: ; \
	else \
		$(LN_S) -rf $(DESTDIR)$(prefix)/include/odp/arch/@ARCH_ABI@/odp/api/abi \
			$(DESTDIR)$(prefix)/include/odp/api/abi; \
	fi
