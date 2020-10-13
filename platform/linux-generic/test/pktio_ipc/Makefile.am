include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

test_PROGRAMS = pktio_ipc1\
		pktio_ipc2

pktio_ipc1_SOURCES = pktio_ipc1.c ipc_common.c ipc_common.h
pktio_ipc2_SOURCES = pktio_ipc2.c ipc_common.c ipc_common.h

dist_check_SCRIPTS = pktio_ipc_run.sh
test_SCRIPTS = $(dist_check_SCRIPTS)

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
