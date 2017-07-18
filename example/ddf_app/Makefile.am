include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_ddf_app$(EXEEXT)
odp_ddf_app_LDFLAGS = $(AM_LDFLAGS) -static
odp_ddf_app_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h

dist_odp_ddf_app_SOURCES = odp_ddf_app.c
