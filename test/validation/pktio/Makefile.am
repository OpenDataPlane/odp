include ../Makefile.inc

noinst_LTLIBRARIES = libpktio.la
libpktio_la_SOURCES = pktio.c

bin_PROGRAMS = pktio_main$(EXEEXT)
dist_pktio_main_SOURCES = pktio_main.c
pktio_main_LDADD = libpktio.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = pktio.h
