# Uncomment this if you need to change the CUSTOM_STR string
#export CUSTOM_STR=https://github.com/OpenDataPlane/odp.git

include $(top_srcdir)/platform/Makefile.inc
lib_LTLIBRARIES += $(LIB)/libodp-linux.la

AM_CPPFLAGS  =  $(ODP_INCLUDES)
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_builddir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/@ARCH_DIR@
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/arch/default

AM_CPPFLAGS +=  $(OPENSSL_CPPFLAGS)
AM_CPPFLAGS +=  $(NETMAP_CPPFLAGS)

AM_CFLAGS +=  $(AARCH64CRYPTO_CFLAGS)
AM_CFLAGS +=  $(DPDK_CFLAGS)
AM_CFLAGS +=  $(LIBCONFIG_CFLAGS)
AM_CFLAGS +=  $(LIBXDP_CFLAGS)

DISTCLEANFILES = include/odp_libconfig_config.h
include/odp_libconfig_config.h: $(top_builddir)/$(rel_default_config_path) $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@

odpapiabiarchincludedir = $(archincludedir)/odp/api/abi
odpapiabiarchinclude_HEADERS =

if !ODP_ABI_COMPAT
odpapiplatincludedir= $(includedir)/odp/api/plat
odpapiplatinclude_HEADERS = \
		  include/odp/api/plat/atomic_inlines.h \
		  include/odp/api/plat/buffer_inlines.h \
		  include/odp/api/plat/buffer_inline_types.h \
		  include/odp/api/plat/byteorder_inlines.h \
		  include/odp/api/plat/cpu_inlines.h \
		  include/odp/api/plat/debug_inlines.h \
		  include/odp/api/plat/event_inlines.h \
		  include/odp/api/plat/event_inline_types.h \
		  include/odp/api/plat/event_vector_inline_types.h \
		  include/odp/api/plat/hash_inlines.h \
		  include/odp/api/plat/ipsec_inlines.h \
		  include/odp/api/plat/packet_flag_inlines.h \
		  include/odp/api/plat/packet_inline_types.h \
		  include/odp/api/plat/packet_inlines.h \
		  include/odp/api/plat/packet_vector_inlines.h \
		  include/odp/api/plat/packet_io_inlines.h \
		  include/odp/api/plat/pool_inlines.h \
		  include/odp/api/plat/pool_inline_types.h \
		  include/odp/api/plat/queue_inlines.h \
		  include/odp/api/plat/queue_inline_types.h \
		  include/odp/api/plat/rwlock_inlines.h \
		  include/odp/api/plat/rwlock_recursive_inlines.h \
		  include/odp/api/plat/schedule_inlines.h \
		  include/odp/api/plat/schedule_inline_types.h \
		  include/odp/api/plat/spinlock_inlines.h \
		  include/odp/api/plat/spinlock_recursive_inlines.h \
		  include/odp/api/plat/std_inlines.h \
		  include/odp/api/plat/strong_types.h \
		  include/odp/api/plat/sync_inlines.h \
		  include/odp/api/plat/thread_inlines.h \
		  include/odp/api/plat/thread_inline_types.h \
		  include/odp/api/plat/ticketlock_inlines.h \
		  include/odp/api/plat/time_inlines.h \
		  include/odp/api/plat/timer_inlines.h \
		  include/odp/api/plat/timer_inline_types.h

odpapiabiarchinclude_HEADERS += \
		  include-abi/odp/api/abi/align.h \
		  include-abi/odp/api/abi/atomic.h \
		  include-abi/odp/api/abi/barrier.h \
		  include-abi/odp/api/abi/buffer.h \
		  include-abi/odp/api/abi/byteorder.h \
		  include-abi/odp/api/abi/classification.h \
		  include-abi/odp/api/abi/comp.h \
		  include-abi/odp/api/abi/cpumask.h \
		  include-abi/odp/api/abi/crypto.h \
		  include-abi/odp/api/abi/crypto_types.h \
		  include-abi/odp/api/abi/debug.h \
		  include-abi/odp/api/abi/dma_types.h \
		  include-abi/odp/api/abi/errno.h \
		  include-abi/odp/api/abi/event.h \
		  include-abi/odp/api/abi/event_types.h \
		  include-abi/odp/api/abi/hash.h \
		  include-abi/odp/api/abi/init.h \
		  include-abi/odp/api/abi/ipsec.h \
		  include-abi/odp/api/abi/ipsec_types.h \
		  include-abi/odp/api/abi/packet.h \
		  include-abi/odp/api/abi/packet_types.h \
		  include-abi/odp/api/abi/packet_flags.h \
		  include-abi/odp/api/abi/packet_io.h \
		  include-abi/odp/api/abi/packet_io_types.h \
		  include-abi/odp/api/abi/proto_stats.h \
		  include-abi/odp/api/abi/proto_stats_types.h \
		  include-abi/odp/api/abi/pool.h \
		  include-abi/odp/api/abi/pool_types.h \
		  include-abi/odp/api/abi/queue.h \
		  include-abi/odp/api/abi/queue_types.h \
		  include-abi/odp/api/abi/random.h \
		  include-abi/odp/api/abi/rwlock.h \
		  include-abi/odp/api/abi/rwlock_recursive.h \
		  include-abi/odp/api/abi/schedule.h \
		  include-abi/odp/api/abi/schedule_types.h \
		  include-abi/odp/api/abi/shared_memory.h \
		  include-abi/odp/api/abi/spinlock.h \
		  include-abi/odp/api/abi/spinlock_recursive.h \
		  include-abi/odp/api/abi/stash.h \
		  include-abi/odp/api/abi/stash_types.h \
		  include-abi/odp/api/abi/std.h \
		  include-abi/odp/api/abi/std_types.h \
		  include-abi/odp/api/abi/sync.h \
		  include-abi/odp/api/abi/thread.h \
		  include-abi/odp/api/abi/thrmask.h \
		  include-abi/odp/api/abi/ticketlock.h \
		  include-abi/odp/api/abi/time.h \
		  include-abi/odp/api/abi/timer.h \
		  include-abi/odp/api/abi/timer_types.h \
		  include-abi/odp/api/abi/traffic_mngr.h \
		  include-abi/odp/api/abi/version.h
endif

noinst_HEADERS = \
		  include/odp_atomic_internal.h \
		  include/odp_bitset.h \
		  include/odp_buffer_internal.h \
		  include/odp_chksum_internal.h \
		  include/odp_classification_datamodel.h \
		  include/odp_classification_internal.h \
		  include/odp_config_internal.h \
		  include/odp_debug_internal.h \
		  include/odp_errno_define.h \
		  include/odp_event_internal.h \
		  include/odp_fdserver_internal.h \
		  include/odp_forward_typedefs_internal.h \
		  include/odp_global_data.h \
		  include/odp_init_internal.h \
		  include/odp_ipsec_internal.h \
		  include/odp_ishmphy_internal.h \
		  include/odp_ishmpool_internal.h \
		  include/odp_libconfig_internal.h \
		  include/odp_llqueue.h \
		  include/odp_macros_internal.h \
		  include/odp_name_table_internal.h \
		  include/odp_packet_dpdk.h \
		  include/odp_packet_internal.h \
		  include/odp_packet_io_internal.h \
		  include/odp_parse_internal.h \
		  include/odp_print_internal.h \
		  include/odp_socket_common.h \
		  include/odp_packet_io_stats_common.h \
		  include/odp_packet_io_stats.h \
		  include/odp_sysfs_stats.h \
		  include/odp_ethtool_stats.h \
		  include/odp_ethtool_rss.h \
		  include/odp_pcapng.h \
		  include/odp_pkt_queue_internal.h \
		  include/odp_pool_internal.h \
		  include/odp_posix_extensions.h \
		  include/odp_queue_if.h \
		  include/odp_queue_basic_internal.h \
		  include/odp_queue_lf.h \
		  include/odp_queue_scalable_internal.h \
		  include/odp_random_std_internal.h \
		  include/odp_random_openssl_internal.h \
		  include/odp_ring_common.h \
		  include/odp_ring_internal.h \
		  include/odp_ring_mpmc_internal.h \
		  include/odp_ring_ptr_internal.h \
		  include/odp_ring_spsc_internal.h \
		  include/odp_ring_st_internal.h \
		  include/odp_ring_u32_internal.h \
		  include/odp_ring_u64_internal.h \
		  include/odp_schedule_if.h \
		  include/odp_schedule_scalable_config.h \
		  include/odp_schedule_scalable.h \
		  include/odp_schedule_scalable_ordered.h \
		  include/odp_shm_internal.h \
		  include/odp_sorted_list_internal.h \
		  include/odp_sysinfo_internal.h \
		  include/odp_timer_internal.h \
		  include/odp_timer_wheel_internal.h \
		  include/odp_traffic_mngr_internal.h \
		  include/odp_types_internal.h \
		  include/odp_event_vector_internal.h \
		  include/protocols/eth.h \
		  include/protocols/ip.h \
		  include/protocols/ipsec.h \
		  include/protocols/sctp.h \
		  include/protocols/tcp.h \
		  include/protocols/thash.h \
		  include/protocols/udp.h
BUILT_SOURCES = \
		  include/odp_libconfig_config.h

__LIB__libodp_linux_la_SOURCES = \
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_chksum.c \
			   odp_classification.c \
			   odp_comp.c \
			   miniz/miniz.c miniz/miniz.h miniz/miniz_common.h \
			   miniz/miniz_tdef.c miniz/miniz_tdef.h \
			   miniz/miniz_tinfl.c miniz/miniz_tinfl.h \
			   odp_cpumask.c \
			   odp_cpumask_task.c \
			   odp_dma.c \
			   odp_errno.c \
			   odp_event.c \
			   odp_fdserver.c \
			   odp_hash_crc_gen.c \
			   odp_impl.c \
			   odp_init.c \
			   odp_ipsec.c \
			   odp_ipsec_events.c \
			   odp_ipsec_sad.c \
			   odp_ishm.c \
			   odp_ishmphy.c \
			   odp_ishmpool.c \
			   odp_libconfig.c \
			   odp_name_table.c \
			   odp_packet.c \
			   odp_packet_vector.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   odp_parse.c \
			   odp_pkt_queue.c \
			   odp_print.c \
			   odp_pool.c \
			   odp_pool_mem_src_ops.c \
			   odp_queue_basic.c \
			   odp_queue_if.c \
			   odp_queue_lf.c \
			   odp_queue_scalable.c \
			   odp_queue_spsc.c \
			   odp_random.c \
			   odp_random_std.c \
			   odp_random_openssl.c \
			   odp_schedule_basic.c \
			   odp_schedule_if.c \
			   odp_schedule_scalable.c \
			   odp_schedule_scalable_ordered.c \
			   odp_schedule_sp.c \
			   odp_shared_memory.c \
			   odp_sorted_list.c \
			   odp_stash.c \
			   odp_std.c \
			   odp_system_info.c \
			   odp_pcapng.c \
			   odp_thread.c \
			   odp_thrmask.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_timer_wheel.c \
			   odp_traffic_mngr.c \
			   odp_version.c \
			   odp_weak.c \
			   pktio/stats/ethtool_stats.c \
			   pktio/stats/sysfs_stats.c \
			   pktio/stats/packet_io_stats.c \
			   pktio/dpdk.c \
			   pktio/socket_common.c \
			   pktio/ethtool_rss.c \
			   pktio/io_ops.c \
			   pktio/ipc.c \
			   pktio/loop.c \
			   pktio/netmap.c \
			   pktio/null.c \
			   pktio/pktio_common.c \
			   pktio/socket.c \
			   pktio/socket_mmap.c \
			   pktio/socket_xdp.c \
			   pktio/tap.c

if WITH_OPENSSL_CRYPTO
__LIB__libodp_linux_la_SOURCES += \
			   odp_crypto_openssl.c
else
if WITH_ARMV8_CRYPTO
__LIB__libodp_linux_la_SOURCES += \
			   arch/aarch64/odp_crypto_armv8.c
else
if WITH_IPSECMB_CRYPTO
__LIB__libodp_linux_la_SOURCES += \
			   odp_crypto_ipsecmb.c
else
__LIB__libodp_linux_la_SOURCES += \
			   odp_crypto_null.c
endif
endif
endif
if ODP_ABI_COMPAT
__LIB__libodp_linux_la_SOURCES += \
			   odp_atomic_api.c \
			   odp_buffer_api.c \
			   odp_byteorder_api.c \
			   odp_cpu_api.c \
			   odp_event_api.c \
			   odp_hash_api.c \
			   odp_ipsec_api.c \
			   odp_packet_api.c \
			   odp_packet_flags_api.c \
			   odp_packet_io_api.c \
			   odp_pool_api.c \
			   odp_queue_api.c \
			   odp_rwlock_api.c \
			   odp_rwlock_recursive_api.c \
			   odp_schedule_api.c \
			   odp_spinlock_api.c \
			   odp_spinlock_recursive_api.c \
			   odp_std_api.c \
			   odp_sync_api.c \
			   odp_thread_api.c \
			   odp_ticketlock_api.c \
			   odp_time_api.c \
			   odp_timer_api.c
endif

if ARCH_IS_ARM
__LIB__libodp_linux_la_SOURCES += arch/default/odp_atomic.c \
				  arch/default/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/default/odp_hash_crc32.c \
				  arch/default/odp_random.c \
				  arch/arm/odp_sysinfo_parse.c
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/cpu_time.h \
				arch/default/odp/api/abi/hash_crc32.h
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/atomic_generic.h \
				arch/default/odp/api/abi/atomic_inlines.h \
				arch/default/odp/api/abi/cpu_generic.h \
				arch/arm/odp/api/abi/cpu_inlines.h \
				arch/arm/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/arm/odp_atomic.h \
		  arch/arm/odp_cpu.h \
		  arch/arm/odp_cpu_idling.h \
		  arch/arm/odp_llsc.h \
		  arch/default/odp_atomic.h \
		  arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h \
		  arch/default/odp_random.h
endif
if ARCH_IS_AARCH64
__LIB__libodp_linux_la_SOURCES += arch/aarch64/odp_atomic.c \
				  arch/default/odp_cpu_cycles.c \
				  arch/aarch64/cpu_flags.c \
				  arch/aarch64/odp_global_time.c \
				  arch/default/odp_hash_crc32.c \
				  arch/default/odp_random.c \
				  arch/aarch64/odp_sysinfo_parse.c
odpapiabiarchinclude_HEADERS += arch/aarch64/odp/api/abi/cpu_time.h \
				arch/aarch64/odp/api/abi/hash_crc32.h
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/atomic_generic.h \
				arch/aarch64/odp/api/abi/atomic_inlines.h \
				arch/aarch64/odp/api/abi/atomic.h \
				arch/default/odp/api/abi/cpu_generic.h \
				arch/aarch64/odp/api/abi/cpu_inlines.h \
				arch/aarch64/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/aarch64/odp_atomic.h \
		  arch/aarch64/odp_cpu.h \
		  arch/aarch64/cpu_flags.h \
		  arch/aarch64/odp_cpu_idling.h \
		  arch/aarch64/odp_llsc.h \
		  arch/aarch64/odp_random.h
endif
if ARCH_IS_DEFAULT
__LIB__libodp_linux_la_SOURCES += arch/default/odp_atomic.c \
				  arch/default/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/default/odp_hash_crc32.c \
				  arch/default/odp_random.c \
				  arch/default/odp_sysinfo_parse.c
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/cpu_time.h \
				arch/default/odp/api/abi/hash_crc32.h
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/atomic_generic.h \
				arch/default/odp/api/abi/atomic_inlines.h \
				arch/default/odp/api/abi/cpu_generic.h \
				arch/default/odp/api/abi/cpu_inlines.h \
				arch/default/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_atomic.h \
		  arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h \
		  arch/default/odp_random.h
endif
if ARCH_IS_POWERPC
__LIB__libodp_linux_la_SOURCES += arch/default/odp_atomic.c \
				  arch/default/odp_cpu_cycles.c \
				  arch/default/odp_global_time.c \
				  arch/default/odp_hash_crc32.c \
				  arch/default/odp_random.c \
				  arch/powerpc/odp_sysinfo_parse.c
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/cpu_time.h \
				arch/default/odp/api/abi/hash_crc32.h
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/atomic_generic.h \
				arch/default/odp/api/abi/atomic_inlines.h \
				arch/default/odp/api/abi/cpu_generic.h \
				arch/default/odp/api/abi/cpu_inlines.h \
				arch/powerpc/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/default/odp_atomic.h \
		  arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h \
		  arch/default/odp_random.h
endif
if ARCH_IS_X86
__LIB__libodp_linux_la_SOURCES += arch/default/odp_atomic.c \
				  arch/x86/cpu_flags.c \
				  arch/x86/odp_cpu_cycles.c \
				  arch/x86/odp_global_time.c \
				  arch/default/odp_hash_crc32.c \
				  arch/default/odp_random.c \
				  arch/x86/odp_sysinfo_parse.c
odpapiabiarchinclude_HEADERS += arch/x86/odp/api/abi/cpu_rdtsc.h \
				arch/x86/odp/api/abi/cpu_time.h \
				arch/x86/odp/api/abi/hash_crc32.h
if !ODP_ABI_COMPAT
odpapiabiarchinclude_HEADERS += arch/default/odp/api/abi/atomic_generic.h \
				arch/default/odp/api/abi/atomic_inlines.h \
				arch/x86/odp/api/abi/cpu_inlines.h \
				arch/x86/odp/api/abi/cpu.h
endif
noinst_HEADERS += arch/x86/cpu_flags.h \
		  arch/x86/odp_cpu.h \
		  arch/x86/odp_random.h \
		  arch/default/odp_atomic.h \
		  arch/default/odp_cpu.h \
		  arch/default/odp_cpu_idling.h
endif

if ODP_PKTIO_PCAP
__LIB__libodp_linux_la_SOURCES += pktio/pcap.c
endif

__LIB__libodp_linux_la_LIBADD =  $(AARCH64CRYPTO_LIBS)
__LIB__libodp_linux_la_LIBADD += $(ATOMIC_LIBS)
__LIB__libodp_linux_la_LIBADD += $(OPENSSL_LIBS)
__LIB__libodp_linux_la_LIBADD += $(LIBCONFIG_LIBS)
__LIB__libodp_linux_la_LIBADD += $(DPDK_LIBS_LIBODP)
__LIB__libodp_linux_la_LIBADD += $(PTHREAD_LIBS)
__LIB__libodp_linux_la_LIBADD += $(TIMER_LIBS)
__LIB__libodp_linux_la_LIBADD += $(LIBXDP_LIBS)
__LIB__libodp_linux_la_LIBADD += $(IPSEC_MB_LIBS)

if ODP_PKTIO_PCAP
__LIB__libodp_linux_la_LIBADD += $(PCAP_LIBS)
endif

CHECK_GLOBALS_REGEX = " (odp_|_odp_|_deprecated_odp_|miniz_|mz_|tdefl_|tinfl_|mp_hdlr_init_odp_pool_ops)"

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	NM="$(NM)" \
	LIB="$(LIB)" \
	lib_LTLIBRARIES="$(lib_LTLIBRARIES)" \
	CHECK_GLOBALS_REGEX=$(CHECK_GLOBALS_REGEX)

dist_check_SCRIPTS = check-globals.sh

TESTS = $(dist_check_SCRIPTS)
