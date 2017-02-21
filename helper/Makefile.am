include $(top_srcdir)/platform/@with_platform@/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodphelper.pc

LIB   = $(top_builddir)/lib
AM_CFLAGS += -I$(srcdir)/include
AM_CFLAGS += -I$(top_srcdir)/platform/@with_platform@/include
AM_CFLAGS += -I$(top_srcdir)/include
AM_CFLAGS += -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@
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
		  $(srcdir)/include/odp/helper/odph_api.h\
		  $(srcdir)/include/odp/helper/odph_cuckootable.h\
		  $(srcdir)/include/odp/helper/odph_hashtable.h\
		  $(srcdir)/include/odp/helper/odph_iplookuptable.h\
		  $(srcdir)/include/odp/helper/odph_lineartable.h\
		  $(srcdir)/include/odp/helper/strong_types.h\
		  $(srcdir)/include/odp/helper/tcp.h\
		  $(srcdir)/include/odp/helper/table.h\
		  $(srcdir)/include/odp/helper/threads.h \
		  $(srcdir)/include/odp/helper/udp.h

if helper_linux
helperinclude_HEADERS += \
		  $(srcdir)/include/odp/helper/linux.h

helperlinuxincludedir = $(includedir)/odp/helper/linux
helperlinuxinclude_HEADERS = \
		  $(srcdir)/include/odp/helper/linux/pthread.h \
		  $(srcdir)/include/odp/helper/linux/process.h
endif

noinst_HEADERS = \
		 $(srcdir)/odph_debug.h \
		 $(srcdir)/odph_list_internal.h

__LIB__libodphelper_la_SOURCES = \
					eth.c \
					ip.c \
					chksum.c \
					hashtable.c \
					lineartable.c \
					cuckootable.c \
					iplookuptable.c \
					threads.c

if helper_linux
__LIB__libodphelper_la_SOURCES += \
				linux/thread.c
endif

lib_LTLIBRARIES = $(LIB)/libodphelper.la
