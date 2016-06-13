include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = chksum$(EXEEXT) \
              cuckootable$(EXEEXT) \
              table$(EXEEXT) \
              thread$(EXEEXT) \
              parse$(EXEEXT)\
              process$(EXEEXT)

COMPILE_ONLY = odpthreads

TESTSCRIPTS = odpthreads_as_processes \
	      odpthreads_as_pthreads

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS =

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

EXTRA_DIST = odpthreads_as_processes odpthreads_as_pthreads

dist_chksum_SOURCES = chksum.c
dist_cuckootable_SOURCES = cuckootable.c
dist_odpthreads_SOURCES = odpthreads.c
odpthreads_LDADD = $(LIB)/libodphelper-linux.la $(LIB)/libodp-linux.la
dist_thread_SOURCES = thread.c
thread_LDADD = $(LIB)/libodphelper-linux.la $(LIB)/libodp-linux.la
dist_process_SOURCES = process.c
dist_parse_SOURCES = parse.c
process_LDADD = $(LIB)/libodphelper-linux.la $(LIB)/libodp-linux.la
dist_table_SOURCES = table.c
