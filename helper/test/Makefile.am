include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

EXECUTABLES = chksum$(EXEEXT) \
              cuckootable$(EXEEXT) \
              parse$(EXEEXT)\
              table$(EXEEXT) \
              iplookuptable$(EXEEXT)

#These are platform specific extensions that are not portable
#They are a convenience to app writers who have chosen to
#restrict their application to Linux.

if helper_extn
EXECUTABLES += @with_helper_platform@/thread$(EXEEXT) \
	       @with_helper_platform@/process$(EXEEXT)
endif

COMPILE_ONLY = odpthreads

TESTSCRIPTS = odpthreads_as_processes \
	      odpthreads_as_pthreads

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS =

test_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

EXTRA_DIST = odpthreads_as_processes odpthreads_as_pthreads

dist_chksum_SOURCES = chksum.c
dist_cuckootable_SOURCES = cuckootable.c
dist_odpthreads_SOURCES = odpthreads.c
odpthreads_LDADD = $(LIB)/libodphelper-@with_helper_platform@.la $(LIB)/libodp-linux.la
dist_parse_SOURCES = parse.c
dist_table_SOURCES = table.c
dist_iplookuptable_SOURCES = iplookuptable.c
