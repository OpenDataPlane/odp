include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ping

odp_ping_SOURCES = odp_ping.c

if test_example
if ODP_PKTIO_PCAP
TESTS = ping_run.sh
endif
endif
EXTRA_DIST = ping_run.sh icmp_echo_req.pcap
