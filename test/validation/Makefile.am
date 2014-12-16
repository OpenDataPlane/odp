include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

if ODP_CUNIT_ENABLED
TESTS = ${bin_PROGRAMS}
check_PROGRAMS = ${bin_PROGRAMS}
bin_PROGRAMS = odp_init odp_queue odp_crypto odp_shm odp_schedule
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
endif

dist_odp_init_SOURCES = odp_init.c
dist_odp_queue_SOURCES = odp_queue.c common/odp_cunit_common.c
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_async_inp.c \
			  crypto/odp_crypto_test_sync_inp.c \
			  crypto/odp_crypto_test_rng.c \
			  odp_crypto.c common/odp_cunit_common.c
dist_odp_shm_SOURCES = odp_shm.c common/odp_cunit_common.c
dist_odp_schedule_SOURCES = odp_schedule.c common/odp_cunit_common.c
