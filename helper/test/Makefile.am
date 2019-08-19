include $(top_srcdir)/test/Makefile.inc

EXECUTABLES = version \
	      debug \
	      chksum \
              cuckootable \
              parse\
              table \
              iplookuptable

#These are platform specific extensions that are not portable
#They are a convenience to app writers who have chosen to
#restrict their application to Linux.

if helper_linux
EXECUTABLES += linux/pthread \
	       linux/process
linux_pthread_SOURCES = linux/pthread.c
linux_process_SOURCES = linux/process.c
endif

COMPILE_ONLY = odpthreads

TESTSCRIPTS = odpthreads_as_processes \
	      odpthreads_as_pthreads

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

test_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

dist_check_SCRIPTS = odpthreads_as_processes odpthreads_as_pthreads

chksum_SOURCES = chksum.c
cuckootable_SOURCES = cuckootable.c
odpthreads_SOURCES = odpthreads.c
parse_SOURCES = parse.c
table_SOURCES = table.c
iplookuptable_SOURCES = iplookuptable.c
version_SOURCES = version.c
debug_SOURCES = debug.c
