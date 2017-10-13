include ../Makefile.inc

test_PROGRAMS = crypto_main$(EXEEXT)
crypto_main_SOURCES = crypto_main.c \
		      crypto.c \
		      crypto.h \
		      odp_crypto_test_inp.c \
		      odp_crypto_test_inp.h \
		      test_vectors.h \
		      test_vectors_len.h
crypto_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
