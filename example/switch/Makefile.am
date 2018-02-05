include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_switch

odp_switch_SOURCES = odp_switch.c

if test_example
if HAVE_PCAP
TESTS = switch_run.sh
endif
endif
EXTRA_DIST = switch_run.sh udp64.pcap
