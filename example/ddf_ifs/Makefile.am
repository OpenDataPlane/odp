LIB   = $(top_builddir)/lib

AM_CPPFLAGS +=  -I$(srcdir) \
		-I$(top_srcdir)/include \
		-I$(top_srcdir)/platform/@with_platform@/include \
		-I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@

lib_LTLIBRARIES = $(LIB)/libddf_ifs.la

noinst_HEADERS = \
		 $(srcdir)/ddf_ifs.h \
		 $(srcdir)/ddf_ifs_enumr_class.h \
		 $(srcdir)/ddf_ifs_enumr_dpdk.h \
		 $(srcdir)/ddf_ifs_enumr_generic.h \
		 $(srcdir)/ddf_ifs_dev_dpdk.h \
		 $(srcdir)/ddf_ifs_devio_direct.h \
		 $(srcdir)/ddf_ifs_driver.h \
		 $(srcdir)/ddf_ifs_api.h

__LIB__libddf_ifs_la_SOURCES = \
		ddf_ifs.c \
		ddf_ifs_enumr_class.c \
		ddf_ifs_enumr_dpdk.c \
		ddf_ifs_enumr_generic.c \
		ddf_ifs_dev_dpdk.c \
		ddf_ifs_devio_direct.c \
		ddf_ifs_driver.c
