include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_l3fwd

odp_l3fwd_SOURCES = \
		    odp_l3fwd.c \
		    odp_l3fwd_db.c \
		    odp_l3fwd_lpm.c \
		    odp_l3fwd_db.h \
		    odp_l3fwd_lpm.h


if test_example
if HAVE_PCAP
TESTS = odp_l3fwd_run.sh
endif
endif

EXTRA_DIST = odp_l3fwd_run.sh udp64.pcap
