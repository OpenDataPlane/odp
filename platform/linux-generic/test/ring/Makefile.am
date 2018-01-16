include $(top_srcdir)/test/Makefile.inc

test_PROGRAMS = ring_main
ring_main_SOURCES = \
		    ring_main.c \
		    ring_suites.c ring_suites.h \
		    ring_basic.c ring_stress.c

PRELDADD += $(LIBCUNIT_COMMON)
