include ../Makefile.inc

noinst_LTLIBRARIES = libpacket.la
libpacket_la_SOURCES = packet.c

bin_PROGRAMS = packet_main$(EXEEXT)
dist_packet_main_SOURCES = packet_main.c
packet_main_LDADD = libpacket.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = packet.h
