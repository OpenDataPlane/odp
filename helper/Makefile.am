include $(top_srcdir)/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libodphelper.pc

AM_CPPFLAGS = \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES) \
	$(LIBCLI_CPPFLAGS)
AM_CFLAGS += $(PTHREAD_CFLAGS)

AM_LDFLAGS += -version-number '$(ODPHELPER_LIBSO_VERSION)'

helperincludedir = $(includedir)/odp/helper/
helperinclude_HEADERS = \
		  include/odp/helper/autoheader_external.h\
		  include/odp/helper/deprecated.h\
		  include/odp/helper/chksum.h\
		  include/odp/helper/odph_debug.h \
		  include/odp/helper/eth.h\
		  include/odp/helper/gtp.h\
		  include/odp/helper/icmp.h\
		  include/odp/helper/igmp.h\
		  include/odp/helper/ip.h\
		  include/odp/helper/ipsec.h\
		  include/odp/helper/macros.h\
		  include/odp/helper/odph_api.h\
		  include/odp/helper/odph_hashtable.h\
		  include/odp/helper/odph_iplookuptable.h\
		  include/odp/helper/odph_lineartable.h\
		  include/odp/helper/sctp.h \
		  include/odp/helper/stress.h\
		  include/odp/helper/string.h\
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

if helper_cli
helperinclude_HEADERS += \
		  include/odp/helper/cli.h
endif

noinst_HEADERS = \
		 include/odph_list_internal.h

__LIB__libodphelper_la_SOURCES = \
					eth.c \
					ip.c \
					chksum.c \
					hashtable.c \
					lineartable.c \
					iplookuptable.c \
					ipsec.c \
					threads.c \
					version.c

if helper_linux
__LIB__libodphelper_la_SOURCES += \
				linux/thread.c
endif

if helper_cli
__LIB__libodphelper_la_SOURCES += \
				cli.c
endif

__LIB__libodphelper_la_LIBADD = $(PTHREAD_LIBS)
__LIB__libodphelper_la_LIBADD += $(LIBCLI_LIBS)

lib_LTLIBRARIES = $(LIB)/libodphelper.la

CHECK_GLOBALS_REGEX = " (odph_|_deprecated_odph_|__odr_asan)"

TESTS_ENVIRONMENT = \
	LIBTOOL="$(LIBTOOL)" \
	NM="$(NM)" \
	LIB="$(LIB)" \
	lib_LTLIBRARIES="$(lib_LTLIBRARIES)" \
	CHECK_GLOBALS_REGEX=$(CHECK_GLOBALS_REGEX)

dist_check_SCRIPTS = check-globals.sh

TESTS = $(dist_check_SCRIPTS)
