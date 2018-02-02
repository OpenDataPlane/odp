include $(top_srcdir)/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libodp-linux.pc

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES = $(LIB)/libodp-linux.la

AM_LDFLAGS = -version-number '$(ODP_LIBSO_VERSION)'

VERSION_SCRIPT = $(srcdir)/../libodp-linux.map
EXTRA_DIST = $(VERSION_SCRIPT)

if ODP_ABI_COMPAT
AM_LDFLAGS += -Wl,--version-script=$(VERSION_SCRIPT)
EXTRA___LIB__libodp_linux_la_DEPENDENCIES = $(VERSION_SCRIPT)
else
AM_LDFLAGS += -export-symbols-regex '^(_deprecated)?_?odp_'
endif

AM_CFLAGS = "-DGIT_HASH=$(VERSION)"
AM_CFLAGS += $(VISIBILITY_CFLAGS)

AM_CFLAGS += @PTHREAD_CFLAGS@

EXTRA_DIST += doc/platform_specific.dox
