include $(top_srcdir)/Makefile.inc

AM_CPPFLAGS =  -I$(top_builddir)/platform/$(with_platform)/include
AM_CPPFLAGS +=  -I$(top_srcdir)/platform/$(with_platform)/include

bin_PROGRAMS = odp_linuxgen_dumpconfig

odp_linuxgen_dumpconfig_SOURCES = dumpconfig.c

TESTS = odp_linuxgen_dumpconfig
