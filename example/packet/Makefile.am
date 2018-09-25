include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_packet_dump \
	       odp_pktio

odp_packet_dump_SOURCES = odp_packet_dump.c

odp_pktio_SOURCES = odp_pktio.c

if test_example
if HAVE_PCAP
TESTS = pktio_run.sh
endif
endif
EXTRA_DIST = pktio_run.sh udp64.pcap
