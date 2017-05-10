include ../Makefile.inc

AM_CPPFLAGS += -Wno-error=missing-field-initializers

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = \
	ipsec_test_in.c \
	ipsec_test_out.c \
	ipsec.c

test_PROGRAMS = ipsec_main$(EXEEXT)
dist_ipsec_main_SOURCES = ipsec_main.c
ipsec_main_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = ipsec.h
