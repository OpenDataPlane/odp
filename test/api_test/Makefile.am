include $(top_srcdir)/test/Makefile.inc

bin_PROGRAMS = odp_shm odp_ring

odp_shm_CFLAGS = $(AM_CFLAGS)
odp_ring_CFLAGS = $(AM_CFLAGS)

odp_shm_LDFLAGS = $(AM_LDFLAGS) -static
odp_ring_LDFLAGS = $(AM_LDFLAGS) -static

noinst_HEADERS = \
		  $(top_srcdir)/test/api_test/odp_common.h \
		  $(top_srcdir)/test/api_test/odp_shm_test.h \
		  $(top_srcdir)/test/test_debug.h

dist_odp_shm_SOURCES = odp_shm_test.c odp_common.c
dist_odp_ring_SOURCES = odp_ring_test.c odp_common.c
