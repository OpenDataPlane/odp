include $(top_srcdir)/Makefile.inc
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
AM_CFLAGS +=  -I$(srcdir)/include/api
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include/api
AM_CFLAGS +=  -I$(top_srcdir)/include

DPDK_LIBS="-lintel_dpdk -ldl"
LIBS += $(DPDK_LIBS)

include_HEADERS = \
		  $(top_srcdir)/platform/linux-dpdk/include/api/odp_buffer.h \
		  $(top_srcdir)/include/odp.h \
		  $(top_srcdir)/include/odp_align.h \
		  $(top_srcdir)/include/odp_atomic.h \
		  $(top_srcdir)/include/odp_barrier.h \
		  $(top_srcdir)/include/odp_buffer_pool.h \
		  $(top_srcdir)/include/odp_byteorder.h \
		  $(top_srcdir)/include/odp_compiler.h \
		  $(top_srcdir)/include/odp_config.h \
		  $(top_srcdir)/include/odp_coremask.h \
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
		  $(top_srcdir)/include/odp_version.h

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
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   ../linux-generic/odp_coremask.c \
			   odp_init.c \
			   odp_linux.c \
			   odp_packet.c \
			   odp_packet_dpdk.c \
			   ../linux-generic/odp_packet_flags.c \
			   odp_packet_io.c \
			   ../linux-generic/odp_packet_socket.c \
			   odp_queue.c \
			   ../linux-generic/odp_ring.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_schedule.c \
			   ../linux-generic/odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_system_info.c \
			   ../linux-generic/odp_thread.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_time.c \
			   ../linux-generic/odp_timer.c
