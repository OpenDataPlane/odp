LIB   = $(top_builddir)/lib

dist_pkgdata_DATA = $(LIB)/libodp.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodp.pc

.PHONY: pkgconfig/libodp.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp.la
