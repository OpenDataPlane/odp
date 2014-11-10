include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(CUNIT_PATH)/include
AM_LDFLAGS += -L$(CUNIT_PATH)/lib

if ODP_CUNIT_ENABLED
TESTS = ${bin_PROGRAMS}
check_PROGRAMS = ${bin_PROGRAMS}
bin_PROGRAMS = odp_init
odp_init_LDFLAGS = $(AM_LDFLAGS) -static -lcunit
endif

dist_odp_init_SOURCES = odp_init.c
