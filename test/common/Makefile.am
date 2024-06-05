include $(top_srcdir)/test/Makefile.inc

noinst_LTLIBRARIES = \
	libbench_common.la

libbench_common_la_SOURCES = bench_common.c bench_common.h

if cunit_support

noinst_LTLIBRARIES += \
	libcunit_common.la \
	libcpumask_common.la \
	libpacket_common.la \
	libtest_common.la \
	libthrmask_common.la

libcunit_common_la_SOURCES = odp_cunit_common.c odp_cunit_common.h
libcunit_common_la_LIBADD = $(CUNIT_LIBS)

libcpumask_common_la_SOURCES = mask_common.c mask_common.h

libpacket_common_la_SOURCES = packet_common.c packet_common.h

libtest_common_la_SOURCES = export_results.c export_results.h

libthrmask_common_la_SOURCES = mask_common.c mask_common.h
libthrmask_common_la_CFLAGS = $(AM_CFLAGS) -DTEST_THRMASK

endif

noinst_HEADERS = test_common_macros.h \
		 test_packet_custom.h \
		 test_packet_ipsec.h \
		 test_packet_ipv4.h \
		 test_packet_ipv4_with_crc.h \
		 test_packet_ipv6.h
