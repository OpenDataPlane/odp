include ../Makefile.inc

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = \
	test_vectors.h \
	ipsec_test_in.c \
	ipsec_test_out.c \
	ipsec.h \
	ipsec.c

test_PROGRAMS = \
	ipsec_sync \
	ipsec_async \
	ipsec_inline_in \
	ipsec_inline_out

ipsec_sync_SOURCES = ipsec_sync.c
ipsec_async_SOURCES = ipsec_async.c
ipsec_inline_in_SOURCES = ipsec_inline_in.c
ipsec_inline_out_SOURCES = ipsec_inline_out.c

PRELDADD += libtestipsec.la
