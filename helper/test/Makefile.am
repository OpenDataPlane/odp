include $(top_srcdir)/test/Makefile.inc

EXECUTABLES = odph_version \
	      odph_debug \
	      odph_chksum \
	      odph_macros \
	      odph_parse \
	      odph_stress

#These are platform specific extensions that are not portable
#They are a convenience to app writers who have chosen to
#restrict their application to Linux.

if helper_linux
if helper_deprecated
EXECUTABLES += linux/odph_pthread \
	       linux/odph_process
linux_odph_pthread_SOURCES = linux/pthread.c
linux_odph_process_SOURCES = linux/process.c
endif
endif

if helper_cli
EXECUTABLES += odph_cli
odph_cli_SOURCES = cli.c
endif

COMPILE_ONLY = odpthreads

TESTSCRIPTS = odpthreads_as_processes \
	      odpthreads_as_pthreads

if test_helper
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

test_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

dist_check_SCRIPTS = odpthreads_as_processes odpthreads_as_pthreads

odph_chksum_SOURCES = chksum.c
odph_macros_SOURCES = macros.c
odpthreads_SOURCES = odpthreads.c
odph_parse_SOURCES = parse.c
odph_stress_SOURCES = stress.c
odph_version_SOURCES = version.c
odph_debug_SOURCES = debug.c

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
