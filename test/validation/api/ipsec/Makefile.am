include ../Makefile.inc

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = ipsec.c

test_PROGRAMS = ipsec_main$(EXEEXT)
dist_ipsec_main_SOURCES = ipsec_main.c
ipsec_main_LDADD = libtestipsec.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = ipsec.h
