include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform}

if ODP_CUNIT_ENABLED
TESTS = odp_init odp_queue odp_crypto odp_shm odp_schedule odp_pktio_run odp_buffer odp_system odp_timer odp_time odp_synchronizers
check_PROGRAMS = ${bin_PROGRAMS}
bin_PROGRAMS = odp_init odp_queue odp_crypto odp_shm odp_schedule odp_pktio odp_buffer odp_system odp_timer odp_time odp_synchronizers
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
odp_buffer_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/buffer
endif

dist_odp_init_SOURCES = odp_init.c
dist_odp_pktio_SOURCES = odp_pktio.c common/odp_cunit_common.c
dist_odp_queue_SOURCES = odp_queue.c common/odp_cunit_common.c
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_async_inp.c \
			  crypto/odp_crypto_test_sync_inp.c \
			  crypto/odp_crypto_test_rng.c \
			  odp_crypto.c common/odp_cunit_common.c
dist_odp_shm_SOURCES = odp_shm.c common/odp_cunit_common.c
dist_odp_schedule_SOURCES = odp_schedule.c common/odp_cunit_common.c
dist_odp_buffer_SOURCES = buffer/odp_buffer_pool_test.c \
			  buffer/odp_buffer_test.c \
			  buffer/odp_packet_test.c \
			  odp_buffer.c common/odp_cunit_common.c
dist_odp_system_SOURCES = odp_system.c common/odp_cunit_common.c
dist_odp_timer_SOURCES = odp_timer.c common/odp_cunit_common.c
dist_odp_time_SOURCES = odp_time.c common/odp_cunit_common.c
dist_odp_synchronizers_SOURCES = odp_synchronizers.c \
				 common/odp_cunit_common.c
