# Copyright (c) 2014, Linaro Limited
# Copyright (c) 2014, Texas Instruments Incorporated
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/Makefile.inc
include Makefile.inc

AM_CFLAGS +=  -I$(srcdir)/include
AM_CFLAGS +=  -I$(srcdir)/include/api
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS +=  -I$(top_srcdir)/platform/linux-generic/include/api
AM_CFLAGS +=  -I$(top_srcdir)/helper/include
KS2_LIBS = -lnwalsa_$(KS2_DEVICE) -lpktlib -lpa -lsa -lcppi_$(KS2_DEVICE) -lqmss_$(KS2_DEVICE) -lrm -lhplib_$(KS2_DEVICE)
LIBS += $(KS2_LIBS)

include_HEADERS = \
		  $(srcdir)/include/api/odp_buffer.h \
		  $(srcdir)/include/api/odp_buffer_pool.h \
		  $(srcdir)/include/api/odp_crypto.h \
		  $(srcdir)/include/api/odp_packet.h \
		  $(srcdir)/include/api/odp_packet_io.h \
		  $(srcdir)/include/api/odp_state.h \
		  $(srcdir)/include/api/odp_ti_mcsdk.h \
		  $(srcdir)/include/api/mcsdk_tune.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_align.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_atomic.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_barrier.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_byteorder.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_compiler.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_config.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_coremask.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_debug.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_hints.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_init.h \
		  $(top_srcdir)/platform/linux-generic/include/api/odp_packet_flags.h \
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
			   odp_buffer.c \
			   odp_buffer_pool.c \
			   odp_crypto.c \
			   odp_init.c \
			   odp_packet.c \
			   odp_packet_io.c \
			   odp_queue.c \
			   mcsdk/mcsdk_init.c \
			   mcsdk/mcsdk_navig.c \
			   mcsdk/mcsdk_rmclient.c \
			   mcsdk/sockutils.c \
			   ../linux-generic/odp_barrier.c \
			   ../linux-generic/odp_coremask.c \
			   ../linux-generic/odp_linux.c \
			   ../linux-generic/odp_packet_flags.c \
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
