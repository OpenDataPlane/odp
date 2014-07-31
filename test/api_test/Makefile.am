include $(top_srcdir)/test/Makefile.inc

bin_PROGRAMS = odp_atomic odp_shm odp_ring odp_timer_ping
odp_atomic_LDFLAGS = $(AM_LDFLAGS) -static
odp_shm_LDFLAGS = $(AM_LDFLAGS) -static
odp_ring_LDFLAGS = $(AM_LDFLAGS) -static
odp_timer_ping_LDFLAGS = $(AM_LDFLAGS) -static

dist_odp_atomic_SOURCES = odp_atomic_test.c odp_common.c
dist_odp_shm_SOURCES = odp_shm_test.c odp_common.c
dist_odp_ring_SOURCES = odp_ring_test.c odp_common.c
dist_odp_timer_ping_SOURCES = odp_timer_ping.c odp_common.c
