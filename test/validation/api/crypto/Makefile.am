include ../Makefile.inc

test_PROGRAMS = crypto_main
crypto_main_SOURCES = \
		      odp_crypto_test_inp.c \
		      crypto_op_test.c \
		      crypto_op_test.h \
		      test_vectors.h \
		      test_vectors_len.h \
		      test_vector_defs.h \
		      test_vector_file.h \
		      util.h \
		      util.c

if LIBCONFIG
AM_CFLAGS += $(LIBCONFIG_CFLAGS)
crypto_main_SOURCES += test_vector_file.c
crypto_main_LDADD = $(LDADD) $(LIBCONFIG_LIBS)
else
crypto_main_SOURCES += test_vector_file_stub.c
endif

EXTRA_DIST = test_vectors.conf

PRELDADD += $(LIBPACKET_COMMON)
