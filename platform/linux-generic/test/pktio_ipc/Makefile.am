include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

test_PROGRAMS = pktio_ipc1\
		pktio_ipc2

pktio_ipc1_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example
pktio_ipc1_LDFLAGS = $(AM_LDFLAGS) -static
pktio_ipc2_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example
pktio_ipc2_LDFLAGS = $(AM_LDFLAGS) -static

noinst_HEADERS = $(top_srcdir)/test/test_debug.h

dist_pktio_ipc1_SOURCES = pktio_ipc1.c ipc_common.c
dist_pktio_ipc2_SOURCES = pktio_ipc2.c ipc_common.c

EXTRA_DIST = ipc_common.h

dist_check_SCRIPTS = pktio_ipc_run
test_SCRIPTS = $(dist_check_SCRIPTS)
