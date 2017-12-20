pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libodphelper.pc

LIB   = $(top_builddir)/lib
AM_CPPFLAGS = \
	-I$(top_builddir)/platform/@with_platform@/include \
	-I$(top_srcdir)/helper/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/include/odp/arch/@ARCH_ABI@ \
	-I$(top_srcdir)/platform/@with_platform@/include \
	-I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@ \
	-I$(top_builddir)/include

AM_LDFLAGS = -version-number '$(ODPHELPER_LIBSO_VERSION)'

helperincludedir = $(includedir)/odp/helper/
helperinclude_HEADERS = \
		  include/odp/helper/chksum.h\
		  include/odp/helper/eth.h\
		  include/odp/helper/icmp.h\
		  include/odp/helper/ip.h\
		  include/odp/helper/ipsec.h\
		  include/odp/helper/odph_api.h\
		  include/odp/helper/odph_cuckootable.h\
		  include/odp/helper/odph_hashtable.h\
		  include/odp/helper/odph_iplookuptable.h\
		  include/odp/helper/odph_lineartable.h\
		  include/odp/helper/strong_types.h\
		  include/odp/helper/tcp.h\
		  include/odp/helper/table.h\
		  include/odp/helper/threads.h \
		  include/odp/helper/udp.h \
		  include/odp/helper/vxlan.h

if helper_linux
helperinclude_HEADERS += \
		  include/odp/helper/linux.h

helperlinuxincludedir = $(includedir)/odp/helper/linux
helperlinuxinclude_HEADERS = \
		  include/odp/helper/linux/pthread.h \
		  include/odp/helper/linux/process.h
endif

noinst_HEADERS = \
		 include/odph_debug.h \
		 include/odph_list_internal.h

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
