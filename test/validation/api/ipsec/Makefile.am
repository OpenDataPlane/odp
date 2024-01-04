include ../Makefile.inc

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = \
	test_vectors.h \
	reass_test_vectors.h \
	ipsec_test_in.c \
	ipsec_test_out.c \
	ipsec.h \
	ipsec.c \
	reass_test_vectors.c

test_PROGRAMS = \
	ipsec_main

ipsec_main_SOURCES = \
	ipsec_main.c

PRELDADD += libtestipsec.la

EXTRA_DIST = \
	ipsec_sync.sh \
	ipsec_async.sh \
	ipsec_inline_in.sh \
	ipsec_inline_out.sh
