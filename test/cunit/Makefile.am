include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(CUNIT_PATH)/include
AM_LDFLAGS += -L$(CUNIT_PATH)/lib -static -lcunit

if ODP_CUNIT_ENABLED
TESTS = ${bin_PROGRAMS}
check_PROGRAMS = ${bin_PROGRAMS}
bin_PROGRAMS = odp_init odp_queue
odp_init_LDFLAGS = $(AM_LDFLAGS)
odp_queue_LDFLAGS = $(AM_LDFLAGS)
endif

dist_odp_init_SOURCES = odp_init.c
dist_odp_queue_SOURCES = odp_queue.c
