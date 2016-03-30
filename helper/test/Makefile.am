include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = chksum$(EXEEXT) \
              thread$(EXEEXT) \
              parse$(EXEEXT)\
              process$(EXEEXT)\
              table$(EXEEXT)

COMPILE_ONLY =

TESTSCRIPTS =

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS =

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)


dist_chksum_SOURCES = chksum.c
dist_thread_SOURCES = thread.c
thread_LDADD = $(LIB)/libodphelper-linux.la $(LIB)/libodp-dpdk.la
dist_process_SOURCES = process.c
dist_parse_SOURCES = parse.c
process_LDADD = $(LIB)/libodphelper-linux.la $(LIB)/libodp-dpdk.la
dist_table_SOURCES = table.c
