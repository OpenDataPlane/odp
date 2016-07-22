include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_time_global$(EXEEXT)
odp_time_global_LDFLAGS = $(AM_LDFLAGS) -static
odp_time_global_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_time_global_SOURCES = time_global_test.c
