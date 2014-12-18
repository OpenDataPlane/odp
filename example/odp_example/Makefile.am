include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_example
odp_example_LDFLAGS = $(AM_LDFLAGS) -static
odp_example_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_example_SOURCES = odp_example.c
