include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(srcdir)/include/api
AM_CFLAGS +=  -I$(top_srcdir)/include

include_HEADERS = \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_align.h \
		  $(top_srcdir)/include/odp_atomic.h \
		  $(top_srcdir)/include/odp_barrier.h \
		  $(top_srcdir)/include/odp_buffer.h \
		  $(top_srcdir)/include/odp_buffer_pool.h \
		  $(top_srcdir)/include/odp_byteorder.h \
		  $(top_srcdir)/include/odp_compiler.h \
		  $(top_srcdir)/include/odp_config.h \
		  $(top_srcdir)/include/odp_coremask.h \
		  $(top_srcdir)/include/odp_crypto.h \
		  $(top_srcdir)/include/odp_debug.h \
		  $(top_srcdir)/include/odp_hints.h \
		  $(top_srcdir)/include/odp_init.h \
		  $(top_srcdir)/include/odp_packet_flags.h \
		  $(top_srcdir)/include/odp_packet.h \
		  $(top_srcdir)/include/odp_packet_io.h \
		  $(top_srcdir)/include/odp_queue.h \
		  $(top_srcdir)/include/odp_rwlock.h \
		  $(top_srcdir)/include/odp_schedule.h \
		  $(top_srcdir)/include/odp_shared_memory.h \
		  $(top_srcdir)/include/odp_spinlock.h \
		  $(top_srcdir)/include/odp_std_types.h \
		  $(top_srcdir)/include/odp_sync.h \
		  $(top_srcdir)/include/odp_system_info.h \
		  $(top_srcdir)/include/odp_thread.h \
		  $(top_srcdir)/include/odp_ticketlock.h \
		  $(top_srcdir)/include/odp_time.h \
		  $(top_srcdir)/include/odp_timer.h \
		  $(top_srcdir)/include/odp_version.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_pktio_types.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_pktio_netmap.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_pktio_socket.h

subdirheadersdir = $(includedir)/helper
subdirheaders_HEADERS = \
			$(top_srcdir)/include/helper/odp_chksum.h \
			$(top_srcdir)/include/helper/odp_eth.h \
			$(top_srcdir)/include/helper/odp_ip.h \
			$(top_srcdir)/include/helper/odp_linux.h \
			$(top_srcdir)/include/helper/odp_packet_helper.h \
			$(top_srcdir)/include/helper/odp_ring.h \
			$(top_srcdir)/include/helper/odp_udp.h

__LIB__libodp_la_SOURCES = \
			   odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   odp_coremask.c \
			   odp_crypto.c \
			   odp_init.c \
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
			   odp_timer.c
