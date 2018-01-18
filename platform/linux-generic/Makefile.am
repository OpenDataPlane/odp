# Uncomment this if you need to change the CUSTOM_STR string
#export CUSTOM_STR=https://github.com/Linaro/odp.git

include $(top_srcdir)/platform/Makefile.inc

AM_CPPFLAGS  =  $(ODP_INCLUDES)
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/@ARCH_DIR@
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/default

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(DPDK_CPPFLAGS)
AM_CPPFLAGS +=  $(NETMAP_CPPFLAGS)

if PKTIO_DPDK
if ARCH_IS_X86
AM_CFLAGS += -msse4.2
endif
endif

if !ODP_ABI_COMPAT
odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  include/odp/api/plat/atomic_inlines.h \
		  include/odp/api/plat/byteorder_inlines.h \
		  include/odp/api/plat/byteorder_inlines_api.h \
		  include/odp/api/plat/packet_flag_inlines.h \
		  include/odp/api/plat/packet_flag_inlines_api.h \
		  include/odp/api/plat/packet_inline_types.h \
		  include/odp/api/plat/packet_inlines.h \
		  include/odp/api/plat/packet_inlines_api.h \
		  include/odp/api/plat/pool_inline_types.h \
		  include/odp/api/plat/std_clib_inlines.h \
		  include/odp/api/plat/strong_types.h \
		  include/odp/api/plat/sync_inlines.h \
		  include/odp/api/plat/ticketlock_inlines.h \
		  include/odp/api/plat/ticketlock_inlines_api.h

odpapiabiarchincludedir = $(archincludedir)/odp/api/abi
odpapiabiarchinclude_HEADERS = \
		  include-abi/odp/api/abi/align.h \
		  include-abi/odp/api/abi/atomic.h \
		  include-abi/odp/api/abi/barrier.h \
		  include-abi/odp/api/abi/buffer.h \
		  include-abi/odp/api/abi/byteorder.h \
		  include-abi/odp/api/abi/classification.h \
		  include-abi/odp/api/abi/cpumask.h \
		  include-abi/odp/api/abi/crypto.h \
		  include-abi/odp/api/abi/debug.h \
		  include-abi/odp/api/abi/event.h \
		  include-abi/odp/api/abi/init.h \
		  include-abi/odp/api/abi/ipsec.h \
		  include-abi/odp/api/abi/packet.h \
		  include-abi/odp/api/abi/packet_flags.h \
		  include-abi/odp/api/abi/packet_io.h \
		  include-abi/odp/api/abi/pool.h \
		  include-abi/odp/api/abi/queue.h \
		  include-abi/odp/api/abi/rwlock.h \
		  include-abi/odp/api/abi/rwlock_recursive.h \
		  include-abi/odp/api/abi/schedule.h \
		  include-abi/odp/api/abi/schedule_types.h \
		  include-abi/odp/api/abi/shared_memory.h \
		  include-abi/odp/api/abi/spinlock.h \
		  include-abi/odp/api/abi/spinlock_recursive.h \
		  include-abi/odp/api/abi/std_clib.h \
		  include-abi/odp/api/abi/std_types.h \
		  include-abi/odp/api/abi/sync.h \
		  include-abi/odp/api/abi/thread.h \
		  include-abi/odp/api/abi/thrmask.h \
		  include-abi/odp/api/abi/ticketlock.h \
		  include-abi/odp/api/abi/time.h \
		  include-abi/odp/api/abi/timer.h \
		  include-abi/odp/api/abi/traffic_mngr.h \
		  include-abi/odp/api/abi/version.h
endif

noinst_HEADERS = \
		  arch/odp_arch_time_internal.h \
		  include/_fdserver_internal.h \
		  include/_ishm_internal.h \
		  include/_ishmphy_internal.h \
		  include/_ishmpool_internal.h \
		  include/odp_align_internal.h \
		  include/odp_atomic_internal.h \
		  include/odp_buffer_inlines.h \
		  include/odp_bitmap_internal.h \
		  include/odp_bitset.h \
		  include/odp_buffer_internal.h \
		  include/odp_classification_datamodel.h \
		  include/odp_classification_inlines.h \
		  include/odp_classification_internal.h \
		  include/odp_config_internal.h \
		  include/odp_crypto_internal.h \
		  include/odp_debug_internal.h \
		  include/odp_errno_define.h \
		  include/odp_forward_typedefs_internal.h \
		  include/odp_internal.h \
		  include/odp_ipsec_internal.h \
		  include/odp_llqueue.h \
		  include/odp_name_table_internal.h \
		  include/odp_packet_internal.h \
		  include/odp_packet_io_internal.h \
		  include/odp_packet_io_ipc_internal.h \
		  include/odp_packet_io_ring_internal.h \
		  include/odp_packet_netmap.h \
		  include/odp_packet_dpdk.h \
		  include/odp_packet_socket.h \
		  include/odp_packet_tap.h \
		  include/odp_packet_null.h \
		  include/odp_pkt_queue_internal.h \
		  include/odp_pool_internal.h \
		  include/odp_posix_extensions.h \
		  include/odp_queue_internal.h \
		  include/odp_queue_scalable_internal.h \
		  include/odp_ring_internal.h \
		  include/odp_queue_if.h \
		  include/odp_schedule_if.h \
		  include/odp_schedule_scalable.h \
		  include/odp_schedule_scalable_config.h \
		  include/odp_schedule_scalable_ordered.h \
		  include/odp_sorted_list_internal.h \
		  include/odp_shm_internal.h \
		  include/odp_timer_internal.h \
		  include/odp_timer_wheel_internal.h \
		  include/odp_traffic_mngr_internal.h \
		  include/protocols/eth.h \
		  include/protocols/ip.h \
		  include/protocols/ipsec.h \
		  include/protocols/tcp.h \
		  include/protocols/thash.h \
		  include/protocols/udp.h

__LIB__libodp_linux_la_SOURCES = \
			   _fdserver.c \
			   _ishm.c \
			   _ishmphy.c \
			   _ishmpool.c \
			   odp_atomic.c \
			   odp_barrier.c \
			   odp_bitmap.c \
			   odp_buffer.c \
			   odp_chksum.c \
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
			   odp_ipsec_events.c \
			   odp_ipsec_sad.c \
			   odp_name_table.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   pktio/ethtool.c \
			   pktio/io_ops.c \
			   pktio/ipc.c \
			   pktio/pktio_common.c \
			   pktio/loop.c \
			   pktio/netmap.c \
			   pktio/null.c \
			   pktio/dpdk.c \
			   pktio/socket.c \
			   pktio/socket_mmap.c \
			   pktio/sysfs.c \
			   pktio/tap.c \
			   pktio/ring.c \
			   odp_pkt_queue.c \
			   odp_pool.c \
			   odp_queue.c \
			   odp_queue_if.c \
			   odp_queue_scalable.c \
			   odp_rwlock.c \
			   odp_rwlock_recursive.c \
			   odp_schedule.c \
			   odp_schedule_if.c \
			   odp_schedule_sp.c \
			   odp_schedule_iquery.c \
			   odp_schedule_scalable.c \
			   odp_schedule_scalable_ordered.c \
			   odp_shared_memory.c \
			   odp_sorted_list.c \
			   odp_spinlock.c \
			   odp_spinlock_recursive.c \
			   odp_system_info.c \
			   odp_thread.c \
			   odp_thrmask.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_timer_wheel.c \
			   odp_traffic_mngr.c \
			   odp_version.c \
			   odp_weak.c

if ODP_ABI_COMPAT
__LIB__libodp_linux_la_SOURCES += \
			   odp_atomic_api.c \
			   odp_byteorder.c \
			   odp_packet_api.c \
			   odp_packet_flags_api.c \
			   odp_std_clib.c \
			   odp_sync.c \
			   odp_ticketlock.c
endif

if ARCH_IS_ARM
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/default/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/arm/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/arm/odp_atomic.h \
		  arch/arm/odp_cpu.h \
		  arch/arm/odp_cpu_idling.h \
		  arch/default/odp_cpu_idling.h \
		  arch/arm/odp_llsc.h
endif
if ARCH_IS_AARCH64
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				  arch/aarch64/odp_global_time.c \
				  arch/default/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/aarch64/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/aarch64/odp_atomic.h \
		  arch/aarch64/odp_cpu.h \
		  arch/aarch64/odp_cpu_idling.h \
		  arch/default/odp_cpu_idling.h \
		  arch/aarch64/odp_llsc.h
endif
if ARCH_IS_MIPS64
__LIB__libodp_linux_la_SOURCES += arch/mips64/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/mips64/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/mips64/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif
if ARCH_IS_POWERPC
__LIB__libodp_linux_la_SOURCES += arch/default/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/powerpc/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/powerpc/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif
if ARCH_IS_X86
__LIB__libodp_linux_la_SOURCES += arch/x86/cpu_flags.c \
				  arch/x86/odp_cpu_cycles.c \
				  arch/x86/odp_global_time.c \
				  arch/x86/odp_sysinfo_parse.c
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/x86/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/x86/cpu_flags.h
noinst_HEADERS += arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif

if HAVE_PCAP
__LIB__libodp_linux_la_SOURCES += pktio/pcap.c
endif

__LIB__libodp_linux_la_LIBADD = $(ATOMIC_LIBS)
__LIB__libodp_linux_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_linux_la_LIBADD += $(DPDK_LIBS_LIBODP)
__LIB__libodp_linux_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_linux_la_LIBADD += $(TIMER_LIBS)

if HAVE_PCAP
__LIB__libodp_linux_la_LIBADD += $(PCAP_LIBS)
endif
