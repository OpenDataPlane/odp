include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_hello$(EXEEXT)
odp_hello_LDFLAGS = $(AM_LDFLAGS) -static
odp_hello_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

dist_odp_hello_SOURCES = odp_hello.c

if test_example
TESTS = odp_hello
endif
