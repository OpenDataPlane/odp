include ../Makefile.inc

noinst_LTLIBRARIES = libcrypto.la
libcrypto_la_SOURCES = crypto.c \
		       odp_crypto_test_inp.c

bin_PROGRAMS = crypto_main$(EXEEXT)
dist_crypto_main_SOURCES = crypto_main.c
crypto_main_LDADD = libcrypto.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = crypto.h odp_crypto_test_inp.h test_vectors.h test_vectors_len.h
