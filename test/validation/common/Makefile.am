AUTOMAKE_OPTIONS = foreign
include $(top_srcdir)/test/Makefile.inc

#libcunit_common_as_main.a is meant to be removed when all tests define
#their own main
noinst_LIBRARIES = libcunit_common.a libcunit_common_as_main.a
libcunit_common_a_CFLAGS = $(AM_CFLAGS) -DMODULE_HAS_OWN_MAIN
libcunit_common_a_SOURCES = odp_cunit_common.c
libcunit_common_as_main_a_CFLAGS = $(AM_CFLAGS)
libcunit_common_as_main_a_SOURCES = odp_cunit_common.c
