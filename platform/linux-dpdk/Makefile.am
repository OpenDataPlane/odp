include $(top_srcdir)/platform/Makefile.inc

PLAT_CFLAGS  = -msse4.2
if SDK_INSTALL_PATH_
PLAT_CFLAGS += -include $(SDK_INSTALL_PATH)/include/rte_config.h
PLAT_CFLAGS += -I$(SDK_INSTALL_PATH)/include
PLAT_CFLAGS += -I$(SDK_INSTALL_PATH)/include/arch
PLAT_CFLAGS += -I$(SDK_INSTALL_PATH)/include/exec-env

AM_LDFLAGS  += -L$(SDK_INSTALL_PATH)/lib
endif

AM_CFLAGS +=  $(PLAT_CFLAGS)
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

DPDK_LIBS="-ldpdk -ldl -lm -lpcap"
LIBS += $(DPDK_LIBS)

include_HEADERS = \
		  $(top_srcdir)/include/odp.h

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(srcdir)/include/odp/align.h \
		  $(srcdir)/include/odp/atomic.h \
		  $(srcdir)/include/odp/barrier.h \
		  $(srcdir)/include/odp/buffer.h \
		  $(srcdir)/include/odp/byteorder.h \
		  $(srcdir)/include/odp/classification.h \
		  $(srcdir)/include/odp/compiler.h \
		  $(srcdir)/include/odp/config.h \
		  $(srcdir)/include/odp/cpu.h \
		  $(srcdir)/include/odp/cpumask.h \
		  $(srcdir)/include/odp/crypto.h \
		  $(srcdir)/include/odp/debug.h \
		  $(srcdir)/include/odp/errno.h \
		  $(srcdir)/include/odp/event.h \
		  $(srcdir)/include/odp/hash.h \
		  $(srcdir)/include/odp/hints.h \
		  $(srcdir)/include/odp/init.h \
		  $(srcdir)/include/odp/packet_flags.h \
		  $(srcdir)/include/odp/packet.h \
		  $(srcdir)/include/odp/packet_io.h \
		  $(srcdir)/include/odp/pool.h \
		  $(srcdir)/include/odp/queue.h \
		  $(srcdir)/include/odp/random.h \
		  $(srcdir)/include/odp/rwlock.h \
		  $(srcdir)/include/odp/schedule.h \
		  $(srcdir)/include/odp/schedule_types.h \
		  $(srcdir)/include/odp/shared_memory.h \
		  $(srcdir)/include/odp/spinlock.h \
		  $(srcdir)/include/odp/std_types.h \
		  $(srcdir)/include/odp/sync.h \
		  $(srcdir)/include/odp/system_info.h \
		  $(srcdir)/include/odp/thread.h \
		  $(srcdir)/include/odp/thrmask.h \
		  $(srcdir)/include/odp/ticketlock.h \
		  $(srcdir)/include/odp/time.h \
		  $(srcdir)/include/odp/timer.h \
		  $(srcdir)/include/odp/version.h

odpplatincludedir= $(includedir)/odp/plat
odpplatinclude_HEADERS = \
		  $(srcdir)/include/odp/plat/atomic_types.h \
		  $(srcdir)/include/odp/plat/barrier_types.h \
		  $(srcdir)/include/odp/plat/buffer_types.h \
		  $(srcdir)/include/odp/plat/byteorder_types.h \
		  $(srcdir)/include/odp/plat/classification_types.h \
		  $(srcdir)/include/odp/plat/cpumask_types.h \
		  $(srcdir)/include/odp/plat/crypto_types.h \
		  $(srcdir)/include/odp/plat/event_types.h \
		  $(srcdir)/include/odp/plat/packet_types.h \
		  $(srcdir)/include/odp/plat/packet_io_types.h \
		  $(srcdir)/include/odp/plat/pool_types.h \
		  $(srcdir)/include/odp/plat/queue_types.h \
		  $(srcdir)/include/odp/plat/rwlock_types.h \
		  $(srcdir)/include/odp/plat/schedule_types.h \
		  $(srcdir)/include/odp/plat/shared_memory_types.h \
		  $(srcdir)/include/odp/plat/spinlock_types.h \
		  $(srcdir)/include/odp/plat/strong_types.h \
		  $(srcdir)/include/odp/plat/thread_types.h \
		  $(srcdir)/include/odp/plat/thrmask_types.h \
		  $(srcdir)/include/odp/plat/ticketlock_types.h \
		  $(srcdir)/include/odp/plat/time_types.h \
		  $(srcdir)/include/odp/plat/timer_types.h \
		  $(srcdir)/include/odp/plat/version_types.h

noinst_HEADERS = \
		  $(srcdir)/include/odp_buffer_internal.h \
		  $(top_srcdir)/platform/linux-generic/include/odp_debug_internal.h \
		  $(srcdir)/include/odp_packet_dpdk.h \
		  $(srcdir)/include/odp_packet_internal.h \
		  $(srcdir)/include/odp_packet_io_internal.h \
		  $(top_srcdir)/platform/linux-generic/include/odp_packet_io_queue.h \
		  $(srcdir)/include/odp_pool_internal.h \
		  ${top_srcdir}/platform/linux-generic/Makefile.inc

subdirheadersdir = $(includedir)/odp/helper
subdirheaders_HEADERS = \
			$(top_srcdir)/helper/include/odp/helper/chksum.h \
			$(top_srcdir)/helper/include/odp/helper/eth.h \
			$(top_srcdir)/helper/include/odp/helper/icmp.h \
			$(top_srcdir)/helper/include/odp/helper/ip.h \
			$(top_srcdir)/helper/include/odp/helper/ipsec.h \
			$(top_srcdir)/helper/include/odp/helper/linux.h \
			$(top_srcdir)/helper/include/odp/helper/ring.h \
			$(top_srcdir)/helper/include/odp/helper/tcp.h \
			$(top_srcdir)/helper/include/odp/helper/udp.h

__LIB__libodp_la_SOURCES = \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   ../linux-generic/odp_cpu.c \
			   ../linux-generic/odp_cpumask.c \
			   ../linux-generic/odp_cpumask_task.c \
			   ../linux-generic/odp_crypto.c \
			   odp_errno.c \
			   ../linux-generic/odp_event.c \
			   ../linux-generic/odp_hash.c \
			   odp_init.c \
			   ../linux-generic/odp_impl.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   odp_pool.c \
			   ../linux-generic/odp_queue.c \
			   ../../helper/ring.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_schedule.c \
			   ../linux-generic/odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_system_info.c \
			   odp_thread.c \
			   ../linux-generic/odp_thrmask.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_time.c \
			   ../linux-generic/odp_timer.c \
			   ../linux-generic/odp_version.c \
			   ../linux-generic/odp_weak.c \
			   ../linux-generic/arch/@ARCH@/odp_cpu_cycles.c
