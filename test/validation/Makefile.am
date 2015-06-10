PRE_LDADD = $(top_builddir)/test/validation/common/libcunit_common_as_main.a
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
	      odp_synchronizers \
	      odp_time \
	      odp_timer \
	      odp_thread \
	      odp_ver_abt_log_dbg

COMPILE_ONLY = odp_pktio

TESTSCRIPTS = odp_pktio_run

if test_vald
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

dist_bin_SCRIPTS = odp_pktio_run

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ODP_CU_COMMON=common/odp_cunit_common.c

odp_buffer_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/buffer
dist_odp_buffer_SOURCES = odp_buffer.c
odp_classification_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/classification
dist_odp_classification_SOURCES = classification/odp_classification_tests.c \
				classification/odp_classification_basic.c \
				odp_classification.c
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_inp.c \
			  odp_crypto.c
dist_odp_init_SOURCES	= init/odp_init.c
dist_odp_init_abort_SOURCES = init/odp_init_abort.c
dist_odp_init_log_SOURCES = init/odp_init_log.c
dist_odp_queue_SOURCES	= odp_queue.c
dist_odp_random_SOURCES = odp_random.c
dist_odp_scheduler_SOURCES = odp_scheduler.c
dist_odp_shared_memory_SOURCES	= odp_shared_memory.c
dist_odp_synchronizers_SOURCES = odp_synchronizers.c
dist_odp_time_SOURCES   = odp_time.c
dist_odp_timer_SOURCES  = odp_timer.c
odp_pktio_LDADD = $(top_builddir)/test/validation/common/libcunit_common.a \
	$(LIB)/libodp.la
dist_odp_pktio_SOURCES	= odp_pktio.c
dist_odp_packet_SOURCES = odp_packet.c
dist_odp_pool_SOURCES = odp_pool.c
dist_odp_cpumask_SOURCES = odp_cpumask.c
dist_odp_thread_SOURCES = odp_thread.c
odp_ver_abt_log_dbg_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/ver_abt_log_dbg
dist_odp_ver_abt_log_dbg_SOURCES  = ver_abt_log_dbg/odp_system.c \
				    ver_abt_log_dbg/odp_errno.c \
                                    ver_abt_log_dbg/odp_ver_abt_log_dbg.c
SUBDIRS = common
