include $(top_srcdir)/platform/@with_platform@/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodphelper-linux-generic.pc

LIB   = $(top_builddir)/lib
AM_CFLAGS  = -I$(srcdir)/include
AM_CFLAGS += -I$(top_srcdir)/platform/@with_platform@/include
AM_CFLAGS += -I$(top_srcdir)/include
AM_CFLAGS += -I$(top_builddir)/platform/@with_platform@/include
AM_CFLAGS += -I$(top_builddir)/include

AM_LDFLAGS += -version-number '$(ODPHELPER_LIBSO_VERSION)'

helperincludedir = $(includedir)/odp/helper/
helperinclude_HEADERS = \
		  $(srcdir)/include/odp/helper/chksum.h\
		  $(srcdir)/include/odp/helper/eth.h\
		  $(srcdir)/include/odp/helper/icmp.h\
		  $(srcdir)/include/odp/helper/ip.h\
		  $(srcdir)/include/odp/helper/ipsec.h\
		  $(srcdir)/include/odp/helper/strong_types.h\
		  $(srcdir)/include/odp/helper/tcp.h\
		  $(srcdir)/include/odp/helper/table.h\
		  $(srcdir)/include/odp/helper/threads.h \
		  $(srcdir)/include/odp/helper/udp.h

if helper_extn
helperinclude_HEADERS += \
	$(srcdir)/include/odp/helper/platform/@with_helper_platform@/threads_extn.h
endif

noinst_HEADERS = \
		 $(srcdir)/odph_debug.h \
		 $(srcdir)/odph_hashtable.h \
		 $(srcdir)/odph_lineartable.h \
		 $(srcdir)/odph_cuckootable.h \
		 $(srcdir)/odph_list_internal.h \
		 $(srcdir)/odph_iplookuptable.h

__LIB__libodphelper_@with_platform@_la_SOURCES = \
					eth.c \
					ip.c \
					chksum.c \
					hashtable.c \
					lineartable.c \
					cuckootable.c \
					iplookuptable.c \
					threads.c

if helper_extn
__LIB__libodphelper_@with_platform@_la_SOURCES += \
					platform/@with_helper_platform@/thread.c
endif

lib_LTLIBRARIES = $(LIB)/libodphelper-@with_platform@.la
