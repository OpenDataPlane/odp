include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform} TEST_DIR=${builddir}

EXECUTABLES = odp_chksum \
              odp_thread \
              odp_process

COMPILE_ONLY =

TESTSCRIPTS =

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS =

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)


dist_odp_process_SOURCES = odp_chksum.c
dist_odp_thread_SOURCES = odp_thread.c
dist_odp_process_SOURCES = odp_process.c
