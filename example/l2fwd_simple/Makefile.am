include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_l2fwd_simple$(EXEEXT)
odp_l2fwd_simple_LDFLAGS = $(AM_LDFLAGS) -static
odp_l2fwd_simple_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_l2fwd_simple_SOURCES = odp_l2fwd_simple.c

if test_example
if HAVE_PCAP
TESTS = l2fwd_simple_run.sh
endif
endif
EXTRA_DIST = l2fwd_simple_run.sh udp64.pcap
