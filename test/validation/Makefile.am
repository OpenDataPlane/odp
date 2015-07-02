PRE_LDADD = $(top_builddir)/test/validation/common/libcunit_common_as_main.a
include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

EXECUTABLES = odp_shared_memory$(EXEEXT) \
	      odp_timer$(EXEEXT) \
	      odp_ver_abt_log_dbg$(EXEEXT)

if test_vald
TESTS = $(EXECUTABLES)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ODP_CU_COMMON=common/odp_cunit_common.c

odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
dist_odp_shared_memory_SOURCES	= odp_shared_memory.c
dist_odp_timer_SOURCES  = odp_timer.c
odp_ver_abt_log_dbg_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/ver_abt_log_dbg
dist_odp_ver_abt_log_dbg_SOURCES  = ver_abt_log_dbg/odp_system.c \
                                    ver_abt_log_dbg/odp_ver_abt_log_dbg.c

ODP_MODULES = buffer \
	      classification \
	      cpumask \
	      crypto \
	      init \
	      queue \
	      packet \
	      pktio \
	      pool \
	      random \
	      scheduler \
	      synchronizers \
	      system \
	      thread

SUBDIRS = common $(ODP_MODULES)
