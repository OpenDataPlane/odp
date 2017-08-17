# Uncomment this if you need to change the CUSTOM_STR string
#export CUSTOM_STR=https://git.linaro.org/lng/odp.git

include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

lib_LTLIBRARIES = $(LIB)/libodp-linux.la

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/frameworks/modular
AM_CFLAGS +=  -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
AM_CFLAGS +=  -I$(top_builddir)/include
AM_CFLAGS +=  -I$(top_srcdir)/arch/@ARCH_DIR@
AM_CFLAGS +=  -Iinclude
AM_CFLAGS +=  -DSYSCONFDIR=\"@sysconfdir@\"
AM_CFLAGS +=  -D_ODP_PKTIO_IPC

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(DPDK_CPPFLAGS)
AM_CPPFLAGS +=  $(NETMAP_CPPFLAGS)
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
		  $(srcdir)/include/odp/api/plat/packet_types.h \
		  $(srcdir)/include/odp/api/plat/packet_io_types.h \
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
		  ${srcdir}/include/_fdserver_internal.h \
		  ${srcdir}/include/_ishm_internal.h \
		  ${srcdir}/include/_ishmphy_internal.h \
		  ${srcdir}/include/_ishmpool_internal.h \
		  ${srcdir}/include/drv_driver_internal.h\
		  ${srcdir}/include/odp_align_internal.h \
		  ${srcdir}/include/odp_atomic_internal.h \
		  ${srcdir}/include/odp_buffer_inlines.h \
		  ${srcdir}/include/odp_bitmap_internal.h \
		  ${srcdir}/include/odp_bitset.h \
		  ${srcdir}/include/odp_buffer_internal.h \
		  ${srcdir}/include/odp_buffer_subsystem.h \
		  ${srcdir}/include/odp_classification_datamodel.h \
		  ${srcdir}/include/odp_classification_inlines.h \
		  ${srcdir}/include/odp_classification_internal.h \
		  ${srcdir}/include/odp_config_internal.h \
		  ${srcdir}/include/odp_crypto_internal.h \
		  ${srcdir}/include/odp_debug_internal.h \
		  ${srcdir}/include/odp_errno_define.h \
		  ${srcdir}/include/odp_forward_typedefs_internal.h \
		  ${srcdir}/include/odp_internal.h \
		  ${srcdir}/include/odp_llqueue.h \
		  ${srcdir}/include/odp_name_table_internal.h \
		  ${srcdir}/include/odp_packet_internal.h \
		  ${srcdir}/include/odp_packet_io_internal.h \
		  ${srcdir}/include/odp_packet_io_ring_internal.h \
		  ${srcdir}/include/odp_packet_dpdk.h \
		  ${srcdir}/include/odp_packet_socket.h \
		  ${srcdir}/include/odp_packet_tap.h \
		  ${srcdir}/include/odp_pktio_ops_ipc.h \
		  ${srcdir}/include/odp_pktio_ops_loopback.h \
		  ${srcdir}/include/odp_pktio_ops_netmap.h \
		  ${srcdir}/include/odp_pktio_ops_subsystem.h \
		  ${srcdir}/include/odp_pkt_queue_internal.h \
		  ${srcdir}/include/odp_queue_subsystem.h \
		  ${srcdir}/include/odp_pool_internal.h \
		  ${srcdir}/include/odp_pool_subsystem.h \
		  ${srcdir}/include/odp_posix_extensions.h \
		  ${srcdir}/include/odp_queue_internal.h \
		  ${srcdir}/include/odp_queue_scalable_internal.h \
		  ${srcdir}/include/odp_ring_internal.h \
		  ${srcdir}/include/odp_queue_if.h \
		  ${srcdir}/include/odp_schedule_if.h \
		  ${srcdir}/include/odp_schedule_scalable.h \
		  ${srcdir}/include/odp_schedule_scalable_config.h \
		  ${srcdir}/include/odp_schedule_scalable_ordered.h \
		  ${srcdir}/include/odp_schedule_subsystem.h \
		  ${srcdir}/include/odp_sorted_list_internal.h \
		  ${srcdir}/include/odp_shm_internal.h \
		  ${srcdir}/include/odp_time_internal.h \
		  ${srcdir}/include/odp_timer_internal.h \
		  ${srcdir}/include/odp_timer_wheel_internal.h \
		  ${srcdir}/include/odp_traffic_mngr_internal.h \
		  ${srcdir}/include/protocols/eth.h \
		  ${srcdir}/include/protocols/ip.h \
		  ${srcdir}/include/protocols/ipsec.h \
		  ${srcdir}/include/protocols/tcp.h \
		  ${srcdir}/include/protocols/thash.h \
		  ${srcdir}/include/protocols/udp.h \
		  ${srcdir}/Makefile.inc

if ARCH_IS_ARM
noinst_HEADERS += ${srcdir}/arch/arm/odp_atomic.h \
		  ${srcdir}/arch/arm/odp_cpu.h \
		  ${srcdir}/arch/arm/odp_cpu_idling.h \
		  ${srcdir}/arch/arm/odp_llsc.h
endif
if ARCH_IS_MIPS64
noinst_HEADERS += ${srcdir}/arch/mips64/odp_cpu.h
endif
if ARCH_IS_POWERPC
noinst_HEADERS += ${srcdir}/arch/powerpc/odp_cpu.h
endif
if ARCH_IS_X86
noinst_HEADERS += ${srcdir}/arch/x86/odp_cpu.h
endif

__LIB__libodp_linux_la_SOURCES = \
			   _fdserver.c \
			   _ishm.c \
			   _ishmphy.c \
			   _ishmpool.c \
			   _modules.c \
			   odp_atomic.c \
			   odp_barrier.c \
			   odp_bitmap.c \
			   buffer/generic.c \
			   buffer/subsystem.c \
			   odp_byteorder.c \
			   odp_classification.c \
			   odp_cpu.c \
			   odp_cpumask.c \
			   odp_cpumask_task.c \
			   odp_crypto.c \
			   odp_errno.c \
			   odp_event.c \
			   odp_hash.c \
			   odp_init.c \
			   odp_impl.c \
			   odp_ipsec.c \
			   odp_name_table.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   pktio/ethtool.c \
			   pktio/subsystem.c \
			   pktio/ipc.c \
			   pktio/pktio_common.c \
			   pktio/loopback.c \
			   pktio/netmap.c \
			   pktio/dpdk.c \
			   pktio/socket.c \
			   pktio/socket_mmap.c \
			   pktio/sysfs.c \
			   pktio/tap.c \
			   pktio/ring.c \
			   pool/generic.c \
			   pool/subsystem.c \
			   odp_pkt_queue.c \
			   odp_queue_if.c \
			   queue/subsystem.c \
			   queue/generic.c \
			   queue/scalable.c \
			   odp_rwlock.c \
			   odp_rwlock_recursive.c \
			   odp_schedule_if.c \
			   schedule/generic.c \
			   schedule/iquery.c \
			   schedule/scalable.c \
			   schedule/scalable_ordered.c \
			   schedule/sp.c \
			   schedule/subsystem.c \
			   odp_shared_memory.c \
			   odp_sorted_list.c \
			   odp_spinlock.c \
			   odp_spinlock_recursive.c \
			   odp_std_clib.c \
			   odp_sync.c \
			   odp_system_info.c \
			   odp_thread.c \
			   odp_thrmask.c \
			   odp_ticketlock.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_timer_wheel.c \
			   odp_traffic_mngr.c \
			   odp_version.c \
			   odp_weak.c \
			   drv_atomic.c \
			   drv_barrier.c \
			   drv_driver.c \
			   drv_shm.c \
			   drv_spinlock.c

if ARCH_IS_ARM
__LIB__libodp_linux_la_SOURCES += arch/arm/odp_cpu_arch.c \
				  arch/arm/odp_sysinfo_parse.c
endif
if ARCH_IS_MIPS64
__LIB__libodp_linux_la_SOURCES += arch/mips64/odp_cpu_arch.c \
				  arch/mips64/odp_sysinfo_parse.c
endif
if ARCH_IS_POWERPC
__LIB__libodp_linux_la_SOURCES += arch/powerpc/odp_cpu_arch.c \
				  arch/powerpc/odp_sysinfo_parse.c
endif
if ARCH_IS_X86
__LIB__libodp_linux_la_SOURCES += arch/x86/cpu_flags.c \
				  arch/x86/odp_cpu_arch.c \
				  arch/x86/odp_sysinfo_parse.c
endif

if HAVE_PCAP
__LIB__libodp_linux_la_SOURCES += pktio/pcap.c
endif

pool/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
buffer/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
if ODP_SCHEDULE_SCALABLE
schedule/scalable.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
schedule/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif
if ODP_SCHEDULE_SP
schedule/sp.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif
if ODP_SCHEDULE_IQUERY
schedule/iquery.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif
if ODP_SCHEDULE_SCALABLE
queue/scalable.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
else
queue/generic.lo: AM_CFLAGS += -DIM_ACTIVE_MODULE
endif

# Build modular framework into odp-linux library
modularframeworkdir = $(top_srcdir)/frameworks/modular
noinst_HEADERS += $(modularframeworkdir)/list.h \
		  $(modularframeworkdir)/odp_module.h

__LIB__libodp_linux_la_SOURCES += ../../frameworks/modular/odp_module.c

__LIB__libodp_linux_la_LIBADD = $(ATOMIC_LIBS)
__LIB__libodp_linux_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_linux_la_LIBADD += $(DPDK_LIBS) $(DPDK_PMDS)
__LIB__libodp_linux_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_linux_la_LIBADD += $(TIMER_LIBS)
__LIB__libodp_linux_la_LIBADD += $(LIBCONFIG_LIBS)

if HAVE_PCAP
__LIB__libodp_linux_la_LIBADD += $(PCAP_LIBS)
endif

# Create symlink for ABI header files. Application does not need to use the arch
# specific include path for installed files.
install-data-hook:
	if [ -h $(DESTDIR)$(prefix)/include/odp/api/abi ]; then \
		: ; \
	else \
		$(LN_S) -rf $(DESTDIR)$(prefix)/include/odp/arch/@ARCH_ABI@/odp/api/abi \
			$(DESTDIR)$(prefix)/include/odp/api/abi; \
	fi
