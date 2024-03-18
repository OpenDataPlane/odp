include $(top_srcdir)/test/Makefile.inc

EXECUTABLES = version \
	      debug \
	      chksum \
	      macros \
	      parse\
	      stress \
	      table

#These are platform specific extensions that are not portable
#They are a convenience to app writers who have chosen to
#restrict their application to Linux.

if helper_linux
EXECUTABLES += linux/pthread \
	       linux/process
linux_pthread_SOURCES = linux/pthread.c
linux_process_SOURCES = linux/process.c
endif

if helper_cli
EXECUTABLES += cli
cli_SOURCES = cli.c
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
macros_SOURCES = macros.c
odpthreads_SOURCES = odpthreads.c
parse_SOURCES = parse.c
stress_SOURCES = stress.c
table_SOURCES = table.c
version_SOURCES = version.c
debug_SOURCES = debug.c

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
