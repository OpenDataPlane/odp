include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_l2fwd_simple

odp_l2fwd_simple_SOURCES = odp_l2fwd_simple.c

if test_example
if HAVE_PCAP
TESTS = l2fwd_simple_run.sh
endif
endif
EXTRA_DIST = l2fwd_simple_run.sh udp64.pcap
