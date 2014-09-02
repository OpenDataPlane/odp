include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc

KS2_PLATFORM  = DEVICE_K2K
if SDK_INSTALL_PATH_
AM_CFLAGS    += -I$(SDK_INSTALL_PATH)/usr/include

AM_LDFLAGS   += -L$(SDK_INSTALL_PATH)/usr/lib
endif

PLAT_CFLAGS  = -D$(KS2_PLATFORM)
PLAT_CFLAGS += -D_GNU_SOURCE -DEM_32_BIT -DTI_EM_CENTRAL_SCHED
PLAT_CFLAGS += -DTI_EM_TRACE_LEVEL=3 -DEM_CHECK_LEVEL=1
PLAT_CFLAGS += -DTI_EM_LINUX -DTI_EM_GCC -DTI_EM_ARM_A15 -DTI_EM_C6638
PLAT_CFLAGS += -D_LITTLE_ENDIAN -DTI_EM_USE_MSM -DTI_EM_XGE_LOOPBACK
PLAT_CFLAGS += -DTI_ODP

AM_CFLAGS +=  $(PLAT_CFLAGS)
AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(srcdir)/include/api
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include/api
AM_CFLAGS +=  -I$(top_srcdir)/helper/include
KS2_LIBS="-lopenem_rh -lopenem_osal"
LIBS += $(KS2_LIBS)

include_HEADERS = \
		  $(srcdir)/include/api/odp_buffer.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_align.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_atomic.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_barrier.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_buffer_pool.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_compiler.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_config.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_coremask.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_debug.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_hints.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_init.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_packet_flags.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_packet.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_packet_io.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_queue.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_rwlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_schedule.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_shared_memory.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_spinlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_std_types.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_sync.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_system_info.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_thread.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_ticketlock.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_time.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_timer.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_version.h

subdirheadersdir = $(includedir)/helper
subdirheaders_HEADERS = \
			$(top_srcdir)/helper/include/odph_chksum.h \
			$(top_srcdir)/helper/include/odph_eth.h \
			$(top_srcdir)/helper/include/odph_ip.h \
			$(top_srcdir)/helper/include/odph_linux.h \
			$(top_srcdir)/helper/include/odph_packet.h \
			$(top_srcdir)/helper/include/odph_ring.h \
			$(top_srcdir)/helper/include/odph_udp.h

__LIB__libodp_la_SOURCES = \
			   ../linux-generic/odp_barrier.c \
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   ../linux-generic/odp_coremask.c \
			   odp_init.c \
			   ../linux-generic/odp_linux.c \
			   odp_packet.c \
			   ../linux-generic/odp_packet_flags.c \
			   odp_packet_io.c \
			   ../linux-generic/odp_packet_socket.c \
			   odp_queue.c \
			   ../linux-generic/odp_ring.c \
			   ../linux-generic/odp_rwlock.c \
			   ../linux-generic/odp_schedule.c \
			   odp_shared_memory.c \
			   ../linux-generic/odp_spinlock.c \
			   ../linux-generic/odp_system_info.c \
			   ../linux-generic/odp_thread.c \
			   ../linux-generic/odp_ticketlock.c \
			   ../linux-generic/odp_time.c \
			   ../linux-generic/odp_timer.c
