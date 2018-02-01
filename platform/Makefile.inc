LIB   = $(top_builddir)/lib

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libodp-dpdk.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp-dpdk.la

AM_LDFLAGS = -version-number '$(ODP_LIBSO_VERSION)'

AM_CFLAGS = "-DGIT_HASH=$(VERSION)"
AM_CFLAGS += $(VISIBILITY_CFLAGS)

AM_CFLAGS += @PTHREAD_CFLAGS@
