include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

test_PROGRAMS = pktio_ipc1\
		pktio_ipc2

pktio_ipc1_SOURCES = pktio_ipc1.c ipc_common.c ipc_common.h
pktio_ipc2_SOURCES = pktio_ipc2.c ipc_common.c ipc_common.h

dist_check_SCRIPTS = pktio_ipc_run.sh
test_SCRIPTS = $(dist_check_SCRIPTS)
