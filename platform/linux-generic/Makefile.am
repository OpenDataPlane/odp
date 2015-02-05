include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/include
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

include_HEADERS = \
		  $(top_srcdir)/include/odp.h

odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/odp/align.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/atomic.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/barrier.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/buffer.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/classification.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/compiler.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/config.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/cpu.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/cpumask.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/crypto.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/debug.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/errno.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/event.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/hints.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/init.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/packet_flags.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/packet.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/packet_io.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/pool.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/queue.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/random.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/rwlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/schedule.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/shared_memory.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/spinlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/std_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/sync.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/system_info.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/thread.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/ticketlock.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/time.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/timer.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/version.h

odpplatincludedir= $(includedir)/odp/plat
odpplatinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/atomic_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/buffer_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/byteorder_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/classification_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/cpumask_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/crypto_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/event_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/packet_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/packet_io_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/pool_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/queue_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/schedule_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/shared_memory_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/strong_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/timer_types.h \
		  $(top_srcdir)/platform/linux-generic/include/odp/plat/version_types.h

odpapiincludedir= $(includedir)/odp/api
odpapiinclude_HEADERS = \
		  $(top_srcdir)/include/odp/api/align.h \
		  $(top_srcdir)/include/odp/api/atomic.h \
		  $(top_srcdir)/include/odp/api/barrier.h \
		  $(top_srcdir)/include/odp/api/buffer.h \
		  $(top_srcdir)/include/odp/api/byteorder.h \
		  $(top_srcdir)/include/odp/api/classification.h \
		  $(top_srcdir)/include/odp/api/compiler.h \
		  $(top_srcdir)/include/odp/api/config.h \
		  $(top_srcdir)/include/odp/api/cpu.h \
		  $(top_srcdir)/include/odp/api/cpumask.h \
		  $(top_srcdir)/include/odp/api/crypto.h \
		  $(top_srcdir)/include/odp/api/debug.h \
		  $(top_srcdir)/include/odp/api/event.h \
		  $(top_srcdir)/include/odp/api/hints.h \
		  $(top_srcdir)/include/odp/api/init.h \
		  $(top_srcdir)/include/odp/api/packet.h \
		  $(top_srcdir)/include/odp/api/packet_flags.h \
		  $(top_srcdir)/include/odp/api/packet_io.h \
		  $(top_srcdir)/include/odp/api/pool.h \
		  $(top_srcdir)/include/odp/api/queue.h \
		  $(top_srcdir)/include/odp/api/random.h \
		  $(top_srcdir)/include/odp/api/rwlock.h \
		  $(top_srcdir)/include/odp/api/schedule.h \
		  $(top_srcdir)/include/odp/api/shared_memory.h \
		  $(top_srcdir)/include/odp/api/spinlock.h \
		  $(top_srcdir)/include/odp/api/std_types.h \
		  $(top_srcdir)/include/odp/api/sync.h \
		  $(top_srcdir)/include/odp/api/system_info.h \
		  $(top_srcdir)/include/odp/api/thread.h \
		  $(top_srcdir)/include/odp/api/ticketlock.h \
		  $(top_srcdir)/include/odp/api/time.h \
		  $(top_srcdir)/include/odp/api/timer.h \
		  $(top_srcdir)/include/odp/api/version.h

noinst_HEADERS = \
		  ${top_srcdir}/platform/linux-generic/include/odp_align_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_atomic_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_buffer_pool_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_datamodel.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_inlines.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_classification_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_crypto_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_debug_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_io_queue.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_packet_socket.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_queue_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_schedule_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_spin_internal.h \
		  ${top_srcdir}/platform/linux-generic/include/odp_timer_internal.h \
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
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   odp_classification.c \
			   odp_cpumask.c \
			   odp_crypto.c \
			   odp_errno.c \
			   odp_event.c \
			   odp_init.c \
			   odp_impl.c \
			   odp_linux.c \
			   odp_packet.c \
			   odp_packet_flags.c \
			   odp_packet_io.c \
			   odp_packet_socket.c \
			   odp_queue.c \
			   odp_ring.c \
			   odp_rwlock.c \
			   odp_schedule.c \
			   odp_shared_memory.c \
			   odp_spinlock.c \
			   odp_system_info.c \
			   odp_thread.c \
			   odp_ticketlock.c \
			   odp_time.c \
			   odp_timer.c \
			   odp_weak.c
