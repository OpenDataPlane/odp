include ../Makefile.inc

noinst_LIBRARIES = libcrypto.a
libcrypto_a_SOURCES = crypto.c \
		      odp_crypto_test_inp.c

bin_PROGRAMS = crypto_main
dist_crypto_main_SOURCES = crypto_main.c
crypto_main_LDADD = libcrypto.a $(LIBCUNIT_COMMON) $(LIBODP)
