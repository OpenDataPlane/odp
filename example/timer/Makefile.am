include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_timer_test$(EXEEXT) \
		odp_timer_simple$(EXEEXT)
odp_timer_test_LDFLAGS = $(AM_LDFLAGS) -static
odp_timer_test_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example
dist_odp_timer_test_SOURCES = odp_timer_test.c

odp_timer_simple_LDFLAGS = $(AM_LDFLAGS) -static
odp_timer_simple_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example
dist_odp_timer_simple_SOURCES = odp_timer_simple.c

if test_example
TESTS = odp_timer_simple
endif

noinst_HEADERS = \
		  $(top_srcdir)/example/example_debug.h
