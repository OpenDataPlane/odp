include $(top_srcdir)/test/Makefile.inc

if cunit_support

noinst_LTLIBRARIES = libcunit_common.la libcpumask_common.la libthrmask_common.la

libcunit_common_la_SOURCES = odp_cunit_common.c odp_cunit_common.h
libcunit_common_la_LIBADD = $(CUNIT_LIBS)

libcpumask_common_la_SOURCES = mask_common.c mask_common.h

libthrmask_common_la_SOURCES = mask_common.c mask_common.h
libthrmask_common_la_CFLAGS = $(AM_CFLAGS) -DTEST_THRMASK

endif

noinst_HEADERS = test_packet_parser.h
dist_test_SCRIPTS = run-test.sh
