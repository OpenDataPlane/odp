LIB   = $(top_builddir)/lib

dist_pkgdata_DATA = $(LIB)/libodp.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/pkgconfig/libodp.pc

.PHONY: pkgconfig/libodp.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp.la

AM_LDFLAGS += -version-number '$(ODP_LIBSO_VERSION)'

GIT_DESC !=$(top_builddir)/scripts/git_hash.sh
AM_CFLAGS += "-DGIT_HASH=$(GIT_DESC)"
AM_CFLAGS += -DPLATFORM=${with_platform}
