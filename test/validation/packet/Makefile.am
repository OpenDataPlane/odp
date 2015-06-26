include ../Makefile.inc

noinst_LIBRARIES = libpacket.a
libpacket_a_SOURCES = packet.c

bin_PROGRAMS = packet_main$(EXEEXT)
dist_packet_main_SOURCES = packet_main.c
packet_main_LDADD = libpacket.a $(LIBCUNIT_COMMON) $(LIBODP)
