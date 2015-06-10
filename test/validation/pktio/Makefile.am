include ../Makefile.inc

dist_bin_SCRIPTS = pktio_run

noinst_LIBRARIES = libpktio.a
libpktio_a_SOURCES = pktio.c

bin_PROGRAMS = pktio_main
dist_pktio_main_SOURCES = pktio_main.c
pktio_main_LDADD = libpktio.a $(LIBCUNIT_COMMON) $(LIBODP)
