include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform}

if test_vald
TESTS = odp_init odp_init_abort odp_init_log odp_queue odp_crypto odp_shm odp_schedule odp_pktio_run odp_pool odp_buffer odp_packet odp_system odp_timer odp_time odp_synchronizers odp_classification
endif

dist_bin_SCRIPTS = $(srcdir)/odp_pktio_run

bin_PROGRAMS = odp_init odp_init_abort odp_init_log odp_queue odp_crypto odp_shm odp_schedule odp_pktio odp_pool odp_buffer odp_packet odp_system odp_timer odp_time odp_synchronizers odp_classification
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
odp_classification_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/classification

dist_odp_init_SOURCES = odp_init.c
dist_odp_init_abort_SOURCES = odp_init_abort.c
dist_odp_pktio_SOURCES = odp_pktio.c common/odp_cunit_common.c
dist_odp_queue_SOURCES = odp_queue.c common/odp_cunit_common.c
dist_odp_pool_SOURCES = odp_pool.c common/odp_cunit_common.c
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_async_inp.c \
			  crypto/odp_crypto_test_sync_inp.c \
			  crypto/odp_crypto_test_rng.c \
			  odp_crypto.c common/odp_cunit_common.c
dist_odp_shm_SOURCES = odp_shm.c common/odp_cunit_common.c
dist_odp_schedule_SOURCES = odp_schedule.c common/odp_cunit_common.c
dist_odp_buffer_SOURCES = odp_buffer.c common/odp_cunit_common.c
dist_odp_packet_SOURCES = odp_packet.c common/odp_cunit_common.c
dist_odp_system_SOURCES = odp_system.c common/odp_cunit_common.c
dist_odp_timer_SOURCES = odp_timer.c common/odp_cunit_common.c
dist_odp_time_SOURCES = odp_time.c common/odp_cunit_common.c
dist_odp_synchronizers_SOURCES = odp_synchronizers.c \
				 common/odp_cunit_common.c
dist_odp_classification_SOURCES = classification/odp_classification_tests.c \
				classification/odp_classification_basic.c \
				odp_classification.c common/odp_cunit_common.c
