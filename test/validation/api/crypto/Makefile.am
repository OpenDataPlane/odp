include ../Makefile.inc

test_PROGRAMS = crypto_main
crypto_main_SOURCES = \
		      odp_crypto_test_inp.c \
		      crypto_op_test.c \
		      crypto_op_test.h \
		      test_vectors.h \
		      test_vectors_len.h \
		      test_vector_defs.h \
		      util.h \
		      util.c

PRELDADD += $(LIBPACKET_COMMON)
