include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_LDFLAGS += -static

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform} TEST_DIR=${builddir}

EXECUTABLES = odp_buffer \
	      odp_classification \
	      odp_cpumask \
	      odp_crypto \
	      odp_init \
	      odp_init_abort \
	      odp_init_log \
	      odp_packet \
	      odp_pool \
	      odp_queue \
	      odp_random \
	      odp_scheduler \
	      odp_shared_memory \
	      odp_system \
	      odp_synchronizers \
	      odp_time \
	      odp_timer \
	      odp_errno \
	      odp_thread

COMPILE_ONLY = odp_pktio

TESTSCRIPTS = odp_pktio_run

if test_vald
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS = odp_pktio_run

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ODP_CU_COMMON=common/odp_cunit_common.c

odp_buffer_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/buffer
dist_odp_buffer_SOURCES = odp_buffer.c $(ODP_CU_COMMON)
odp_classification_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/classification
dist_odp_classification_SOURCES = classification/odp_classification_tests.c \
				classification/odp_classification_basic.c \
				odp_classification.c $(ODP_CU_COMMON)
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_inp.c \
			  odp_crypto.c $(ODP_CU_COMMON)
dist_odp_init_SOURCES	= odp_init.c
dist_odp_init_abort_SOURCES = odp_init_abort.c
dist_odp_init_log_SOURCES = odp_init_log.c
dist_odp_queue_SOURCES	= odp_queue.c $(ODP_CU_COMMON)
dist_odp_random_SOURCES = odp_random.c $(ODP_CU_COMMON)
dist_odp_scheduler_SOURCES = odp_scheduler.c $(ODP_CU_COMMON)
dist_odp_shared_memory_SOURCES	= odp_shared_memory.c $(ODP_CU_COMMON)
dist_odp_system_SOURCES = odp_system.c $(ODP_CU_COMMON)
dist_odp_synchronizers_SOURCES = odp_synchronizers.c $(ODP_CU_COMMON)
dist_odp_time_SOURCES   = odp_time.c $(ODP_CU_COMMON)
dist_odp_timer_SOURCES  = odp_timer.c $(ODP_CU_COMMON)
dist_odp_pktio_SOURCES	= odp_pktio.c $(ODP_CU_COMMON)
dist_odp_packet_SOURCES = odp_packet.c $(ODP_CU_COMMON)
dist_odp_pool_SOURCES = odp_pool.c $(ODP_CU_COMMON)
dist_odp_errno_SOURCES = odp_errno.c $(ODP_CU_COMMON)
dist_odp_cpumask_SOURCES = odp_cpumask.c $(ODP_CU_COMMON)
dist_odp_thread_SOURCES = odp_thread.c $(ODP_CU_COMMON)
