include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(srcdir)/include/api
AM_CFLAGS +=  -I$(top_srcdir)/helper/include

include_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/api/odp.h
odpincludedir= $(includedir)/odp
odpinclude_HEADERS = \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/align.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/atomic.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/barrier.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/buffer.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/pool.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/classification.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/compiler.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/config.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/cpumask.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/crypto.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/debug.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/event.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/hints.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/init.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/packet_flags.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/packet.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/packet_io.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/queue.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/rwlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/schedule.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/shared_memory.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/spinlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/std_types.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/sync.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/system_info.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/thread.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/ticketlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/time.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/timer.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/platform_types.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp/version.h

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

subdirheadersdir = $(includedir)
subdirheaders_HEADERS = \
			$(top_srcdir)/helper/include/odph_chksum.h \
			$(top_srcdir)/helper/include/odph_eth.h \
			$(top_srcdir)/helper/include/odph_icmp.h \
			$(top_srcdir)/helper/include/odph_ip.h \
			$(top_srcdir)/helper/include/odph_ipsec.h \
			$(top_srcdir)/helper/include/odph_linux.h \
			$(top_srcdir)/helper/include/odph_ring.h \
			$(top_srcdir)/helper/include/odph_tcp.h \
			$(top_srcdir)/helper/include/odph_udp.h

__LIB__libodp_la_SOURCES = \
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   odp_classification.c \
			   odp_cpumask.c \
			   odp_crypto.c \
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
