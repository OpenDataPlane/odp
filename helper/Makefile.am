pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodphelper.pc

LIB   = $(top_builddir)/lib
AM_CFLAGS  = -I$(srcdir)/include
AM_CFLAGS += -I$(top_srcdir)/platform/@with_platform@/include
AM_CFLAGS += -I$(top_srcdir)/platform/linux-generic/include
AM_CFLAGS += -I$(top_srcdir)/include

helperincludedir = $(includedir)/odp/helper/
helperinclude_HEADERS = \
		  $(srcdir)/include/odp/helper/ring.h \
		  $(srcdir)/include/odp/helper/linux.h \
		  $(srcdir)/include/odp/helper/chksum.h\
		  $(srcdir)/include/odp/helper/eth.h\
		  $(srcdir)/include/odp/helper/icmp.h\
		  $(srcdir)/include/odp/helper/ip.h\
		  $(srcdir)/include/odp/helper/ipsec.h\
		  $(srcdir)/include/odp/helper/tcp.h\
		  $(srcdir)/include/odp/helper/udp.h

noinst_HEADERS = \
		 $(srcdir)/odph_debug.h \
		 $(srcdir)/odph_pause.h

__LIB__libodphelper_la_SOURCES = \
					linux.c \
					ring.c

lib_LTLIBRARIES = $(LIB)/libodphelper.la
