include ../Makefile.inc

test_PROGRAMS = ring_main
ring_main_SOURCES = \
		    ring_main.c \
		    ring_suites.c ring_suites.h \
		    ring_basic.c ring_stress.c

ring_main_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_builddir)/include \
		     -I$(top_srcdir)/platform/linux-generic/include \
		     $(INCCUNIT_COMMON) $(ODP_INCLUDES) $(HELPER_INCLUDES)
ring_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
