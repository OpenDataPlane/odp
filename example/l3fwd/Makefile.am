include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_l3fwd$(EXEEXT)
odp_l3fwd_LDFLAGS = $(AM_LDFLAGS) -static
odp_l3fwd_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example -I${top_srcdir}/test

noinst_HEADERS = \
		  $(top_srcdir)/example/l3fwd/odp_l3fwd_db.h \
		  $(top_srcdir)/example/l3fwd/odp_l3fwd_lpm.h \
		  $(top_srcdir)/example/example_debug.h

dist_odp_l3fwd_SOURCES = odp_l3fwd.c odp_l3fwd_db.c odp_l3fwd_lpm.c

if test_example
if HAVE_PCAP
TESTS = odp_l3fwd_run.sh
endif
endif

EXTRA_DIST = odp_l3fwd_run.sh udp64.pcap
