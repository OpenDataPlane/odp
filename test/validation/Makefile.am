PRE_LDADD = $(top_builddir)/test/validation/common/libcunit_common_as_main.a
include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

EXECUTABLES = odp_buffer$(EXEEXT) \
	      odp_cpumask$(EXEEXT) \
	      odp_packet$(EXEEXT) \
	      odp_pool$(EXEEXT) \
	      odp_scheduler$(EXEEXT) \
	      odp_shared_memory$(EXEEXT) \
	      odp_synchronizers$(EXEEXT) \
	      odp_timer$(EXEEXT) \
	      odp_thread$(EXEEXT) \
	      odp_ver_abt_log_dbg$(EXEEXT)

if test_vald
TESTS = $(EXECUTABLES)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ODP_CU_COMMON=common/odp_cunit_common.c

odp_buffer_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/buffer
dist_odp_buffer_SOURCES = odp_buffer.c
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
dist_odp_scheduler_SOURCES = odp_scheduler.c
dist_odp_shared_memory_SOURCES	= odp_shared_memory.c
dist_odp_synchronizers_SOURCES = odp_synchronizers.c
dist_odp_timer_SOURCES  = odp_timer.c
dist_odp_packet_SOURCES = odp_packet.c
odp_pool_LDADD = $(top_builddir)/test/validation/common/libcunit_common.a \
		 $(LIB)/libodp.la
dist_odp_pool_SOURCES = odp_pool.c
dist_odp_cpumask_SOURCES = odp_cpumask.c
dist_odp_thread_SOURCES = odp_thread.c
odp_ver_abt_log_dbg_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/ver_abt_log_dbg
dist_odp_ver_abt_log_dbg_SOURCES  = ver_abt_log_dbg/odp_system.c \
				    ver_abt_log_dbg/odp_errno.c \
                                    ver_abt_log_dbg/odp_ver_abt_log_dbg.c

ODP_MODULES = classification \
	      crypto \
	      init \
	      queue \
	      pktio \
	      random \
	      system

SUBDIRS = common $(ODP_MODULES)
