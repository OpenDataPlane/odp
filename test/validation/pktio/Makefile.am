include ../Makefile.inc

noinst_LIBRARIES = libpktio.a
libpktio_a_SOURCES = pktio.c

bin_PROGRAMS = pktio_main$(EXEEXT)
dist_pktio_main_SOURCES = pktio_main.c
pktio_main_LDADD = libpktio.a $(LIBCUNIT_COMMON) $(LIBODP)
