include $(top_srcdir)/test/Makefile.inc

AM_CFLAGS += -I$(CUNIT_PATH)/include
AM_LDFLAGS += -L$(CUNIT_PATH)/lib -static -lcunit

if ODP_CUNIT_ENABLED
TESTS = ${bin_PROGRAMS}
check_PROGRAMS = ${bin_PROGRAMS}
bin_PROGRAMS = odp_init odp_queue odp_crypto
odp_init_LDFLAGS = $(AM_LDFLAGS)
odp_queue_LDFLAGS = $(AM_LDFLAGS)
odp_crypto_CFLAGS = $(AM_CFLAGS) -I$(srcdir)/crypto
odp_crypto_LDFLAGS = $(AM_LDFLAGS)
endif

dist_odp_init_SOURCES = odp_init.c
dist_odp_queue_SOURCES = odp_queue.c
dist_odp_crypto_SOURCES = crypto/odp_crypto_test_async_inp.c \
			  crypto/odp_crypto_test_sync_inp.c \
			  odp_crypto.c
