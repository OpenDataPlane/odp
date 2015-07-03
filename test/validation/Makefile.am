PRE_LDADD = $(top_builddir)/test/validation/common/libcunit_common_as_main.a
include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

EXECUTABLES = odp_timer$(EXEEXT)

if test_vald
TESTS = $(EXECUTABLES)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ODP_CU_COMMON=common/odp_cunit_common.c

odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
odp_timer_LDADD = $(top_builddir)/test/validation/common/libcunit_common.a \
		  $(LIB)/libodp.la
dist_odp_timer_SOURCES  = odp_timer.c

ODP_MODULES = buffer \
	      classification \
	      cpumask \
	      crypto \
	      errno \
	      init \
	      queue \
	      packet \
	      pktio \
	      pool \
	      random \
	      scheduler \
	      synchronizers \
	      thread \
	      time \
	      shmem \
	      system

SUBDIRS = common $(ODP_MODULES)
