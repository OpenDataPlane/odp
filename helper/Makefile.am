include $(top_srcdir)/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libodphelper.pc

AM_CPPFLAGS = \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES)
AM_CFLAGS = $(PTHREAD_CFLAGS)

AM_LDFLAGS = -version-number '$(ODPHELPER_LIBSO_VERSION)'

helperincludedir = $(includedir)/odp/helper/
helperinclude_HEADERS = \
		  include/odp/helper/chksum.h\
		  include/odp/helper/odph_debug.h \
		  include/odp/helper/eth.h\
		  include/odp/helper/icmp.h\
		  include/odp/helper/ip.h\
		  include/odp/helper/ipsec.h\
		  include/odp/helper/odph_api.h\
		  include/odp/helper/odph_cuckootable.h\
		  include/odp/helper/odph_hashtable.h\
		  include/odp/helper/odph_iplookuptable.h\
		  include/odp/helper/odph_lineartable.h\
		  include/odp/helper/sctp.h \
		  include/odp/helper/strong_types.h\
		  include/odp/helper/tcp.h\
		  include/odp/helper/table.h\
		  include/odp/helper/threads.h \
		  include/odp/helper/udp.h \
		  include/odp/helper/version.h

if helper_linux
helperinclude_HEADERS += \
		  include/odp/helper/linux.h

helperlinuxincludedir = $(includedir)/odp/helper/linux
helperlinuxinclude_HEADERS = \
		  include/odp/helper/linux/pthread.h \
		  include/odp/helper/linux/process.h
endif

noinst_HEADERS = \
		 include/odph_list_internal.h

__LIB__libodphelper_la_SOURCES = \
					eth.c \
					ip.c \
					chksum.c \
					hashtable.c \
					lineartable.c \
					cuckootable.c \
					iplookuptable.c \
					threads.c \
					version.c

if helper_linux
__LIB__libodphelper_la_SOURCES += \
				linux/thread.c
endif

__LIB__libodphelper_la_LIBADD = $(PTHREAD_LIBS) $(LIB)/libodp-linux.la

lib_LTLIBRARIES = $(LIB)/libodphelper.la
