include $(top_srcdir)/test/Makefile.inc

if test_cpp
bin_PROGRAMS =  odp_api_from_cpp
TESTS = odp_api_from_cpp
endif

odp_api_from_cpp_SOURCES = odp_api_from_cpp.cpp

noinst_PROGRAMS = odp_api_headers
odp_api_headers_CFLAGS = $(AM_CFLAGS) -Wconversion
odp_api_headers_SOURCES = odp_api_headers.c
