include $(top_srcdir)/platform/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc

AM_CFLAGS +=  $(DPDK_CFLAGS)

AM_CPPFLAGS =  -I$(srcdir)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CPPFLAGS +=  -I$(top_srcdir)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch
AM_CPPFLAGS +=  -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
AM_CPPFLAGS +=  -I$(top_builddir)/include
AM_CPPFLAGS +=  -Iinclude
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/$(ARCH_DIR)
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/default

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(DPDK_CPPFLAGS)

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  include/odp/visibility_begin.h \
		  include/odp/visibility_end.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  include/odp/api/align.h \
		  include/odp/api/atomic.h \
		  include/odp/api/barrier.h \
		  include/odp/api/buffer.h \
		  include/odp/api/byteorder.h \
		  include/odp/api/chksum.h \
		  include/odp/api/classification.h \
		  include/odp/api/compiler.h \
		  include/odp/api/cpu.h \
		  include/odp/api/cpumask.h \
		  include/odp/api/crypto.h \
		  include/odp/api/debug.h \
		  include/odp/api/deprecated.h \
		  include/odp/api/errno.h \
		  include/odp/api/event.h \
		  include/odp/api/feature.h \
		  include/odp/api/hash.h \
		  include/odp/api/hints.h \
		  include/odp/api/init.h \
		  include/odp/api/ipsec.h \
		  include/odp/api/packet_flags.h \
		  include/odp/api/packet.h \
		  include/odp/api/packet_io.h \
		  include/odp/api/packet_io_stats.h \
		  include/odp/api/pool.h \
		  include/odp/api/queue.h \
		  include/odp/api/random.h \
		  include/odp/api/rwlock.h \
		  include/odp/api/rwlock_recursive.h \
		  include/odp/api/schedule.h \
		  include/odp/api/schedule_types.h \
		  include/odp/api/shared_memory.h \
		  include/odp/api/spinlock.h \
		  include/odp/api/spinlock_recursive.h \
		  include/odp/api/std_clib.h \
		  include/odp/api/std_types.h \
		  include/odp/api/support.h \
		  include/odp/api/sync.h \
		  include/odp/api/system_info.h \
		  include/odp/api/thread.h \
		  include/odp/api/threshold.h \
		  include/odp/api/thrmask.h \
		  include/odp/api/ticketlock.h \
		  include/odp/api/time.h \
		  include/odp/api/timer.h \
		  include/odp/api/traffic_mngr.h \
		  include/odp/api/version.h

odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  include/odp/api/plat/atomic_inlines.h \
		  include/odp/api/plat/atomic_types.h \
		  include/odp/api/plat/barrier_types.h \
		  include/odp/api/plat/buffer_types.h \
		  include/odp/api/plat/byteorder_inlines.h \
		  include/odp/api/plat/byteorder_types.h \
		  include/odp/api/plat/classification_types.h \
		  include/odp/api/plat/cpumask_types.h \
		  include/odp/api/plat/crypto_types.h \
		  include/odp/api/plat/event_types.h \
		  include/odp/api/plat/init_types.h \
		  include/odp/api/plat/ipsec_types.h \
		  include/odp/api/plat/packet_flag_inlines.h \
		  include/odp/api/plat/packet_flag_inlines_api.h \
		  include/odp/api/plat/packet_inlines.h \
		  include/odp/api/plat/packet_inlines_api.h \
		  include/odp/api/plat/packet_io_types.h \
		  include/odp/api/plat/packet_types.h \
		  include/odp/api/plat/pool_types.h \
		  include/odp/api/plat/queue_types.h \
		  include/odp/api/plat/rwlock_types.h \
		  include/odp/api/plat/rwlock_recursive_types.h \
		  include/odp/api/plat/schedule_types.h \
		  include/odp/api/plat/shared_memory_types.h \
		  include/odp/api/plat/spinlock_types.h \
		  include/odp/api/plat/spinlock_recursive_types.h \
		  include/odp/api/plat/std_clib_inlines.h \
		  include/odp/api/plat/strong_types.h \
		  include/odp/api/plat/sync_inlines.h \
		  include/odp/api/plat/thread_types.h \
		  include/odp/api/plat/thrmask_types.h \
		  include/odp/api/plat/ticketlock_inlines.h \
		  include/odp/api/plat/ticketlock_inlines_api.h \
		  include/odp/api/plat/ticketlock_types.h \
		  include/odp/api/plat/time_types.h \
		  include/odp/api/plat/timer_types.h \
		  include/odp/api/plat/traffic_mngr_types.h \
		  include/odp/api/plat/version_types.h

nodist_odpapiplatinclude_HEADERS = \
		  include/odp/api/plat/static_inline.h

noinst_HEADERS = \
		  arch/odp_arch_time_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  include/odp_buffer_inlines.h \
		  include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_bitmap_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_bitset.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  include/odp_config_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_forward_typedefs_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_ipsec_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_llqueue.h \
		  include/odp_packet_dpdk.h \
		  include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_name_table_internal.h \
		  include/odp_packet_io_internal.h \
		  include/odp_errno_define.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ipc_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_pkt_queue_internal.h \
		  include/odp_pool_internal.h \
		  include/odp_posix_extensions.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_ring_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_if.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_sorted_list_internal.h \
		  include/odp_shm_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_wheel_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_traffic_mngr_internal.h \
		  include/protocols/eth.h \
		  include/protocols/ip.h \
		  include/protocols/ipsec.h \
		  include/protocols/tcp.h \
		  include/protocols/thash.h \
		  include/protocols/udp.h \
		  Makefile.inc

__LIB__libodp_dpdk_la_SOURCES = \
			   ../linux-generic/odp_atomic.c \
			   ../linux-generic/odp_barrier.c \
			   ../linux-generic/odp_bitmap.c \
			   odp_buffer.c \
			   ../linux-generic/odp_byteorder.c \
			   ../linux-generic/odp_chksum.c \
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
			   ../linux-generic/odp_ipsec_events.c \
			   ../linux-generic/odp_ipsec_sad.c \
			   ../linux-generic/odp_name_table.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   odp_packet_flags.c \
			   ../linux-generic/odp_packet_io.c \
			   ../linux-generic/pktio/loop.c \
			   ../linux-generic/odp_pkt_queue.c \
			   odp_pool.c \
			   ../linux-generic/odp_queue.c \
			   ../linux-generic/odp_queue_if.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_rwlock_recursive.c \
			   ../linux-generic/odp_schedule.c \
			   ../linux-generic/odp_schedule_if.c \
			   ../linux-generic/odp_schedule_sp.c \
			   ../linux-generic/odp_schedule_iquery.c \
			   odp_shared_memory.c \
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
			   ../linux-generic/odp_weak.c

if ARCH_IS_ARM
__LIB__libodp_dpdk_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/default/odp_sysinfo_parse.c
arch_odp_headers = arch/arm/odp/api/cpu_arch.h
noinst_HEADERS += arch/arm/odp_atomic.h \
		  arch/arm/odp_cpu.h \
		  arch/arm/odp_cpu_idling.h \
		  arch/arm/odp_llsc.h
endif
if ARCH_IS_AARCH64
__LIB__libodp_dpdk_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/aarch64/odp_global_time.c \
				 arch/default/odp_sysinfo_parse.c
arch_odp_headers = arch/aarch64/odp/api/cpu_arch.h
endif
if ARCH_IS_MIPS64
__LIB__libodp_dpdk_la_SOURCES += arch/mips64/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/mips64/odp_sysinfo_parse.c
arch_odp_headers = arch/mips64/odp/api/cpu_arch.h
noinst_HEADERS += arch/mips64/odp_cpu.h
endif
if ARCH_IS_POWERPC
__LIB__libodp_dpdk_la_SOURCES += arch/default/odp_cpu_cycles.c \
				 arch/default/odp_global_time.c \
				 arch/powerpc/odp_sysinfo_parse.c
arch_odp_headers = arch/powerpc/odp/api/cpu_arch.h
noinst_HEADERS += arch/powerpc/odp_cpu.h
endif
if ARCH_IS_X86
__LIB__libodp_dpdk_la_SOURCES += arch/x86/cpu_flags.c \
				 arch/x86/odp_cpu_cycles.c \
				 arch/x86/odp_global_time.c \
				 arch/x86/odp_sysinfo_parse.c
arch_odp_headers = arch/x86/odp/api/cpu_arch.h
noinst_HEADERS += arch/x86/cpu_flags.h
noinst_HEADERS += arch/x86/odp_cpu.h
endif

noinst_HEADERS += arch/default/odp/api/cpu_arch.h

odpapiinclude_HEADERS += $(arch_odp_headers)

__LIB__libodp_dpdk_la_LIBADD = $(ATOMIC_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(DPDK_LIBS) $(DPDK_PMDS)
__LIB__libodp_dpdk_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_dpdk_la_LIBADD += $(TIMER_LIBS)
