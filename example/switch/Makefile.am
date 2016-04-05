include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_switch$(EXEEXT)
odp_switch_LDFLAGS = $(AM_LDFLAGS) -static
odp_switch_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_switch_SOURCES = odp_switch.c

if HAVE_PCAP
TESTS = switch_run.sh
endif
EXTRA_DIST = switch_run.sh udp64.pcap
