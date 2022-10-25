include $(top_srcdir)/Makefile.inc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lib$(ODP_LIB_NAME).pc

EXTRA_DIST = doc/platform_specific.dox

configdir = $(sysconfdir)/odp
if ODP_USE_CONFIG
config_DATA = $(top_builddir)/$(rel_default_config_path)
EXTRA_DIST += $(top_builddir)/$(rel_default_config_path)
endif

VPATH = $(srcdir) $(builddir)
lib_LTLIBRARIES =

AM_LDFLAGS += -version-number '$(ODP_LIBSO_VERSION)'

if ODP_ABI_COMPAT
AM_LDFLAGS += -export-symbols-regex '^(odp_|_deprecated_odp_)'
else
AM_LDFLAGS += -export-symbols-regex '^(odp_|_odp_|_deprecated_odp_)'
endif

AM_CFLAGS += "-DODP_VERSION_BUILD=$(VERSION)"
AM_CFLAGS += $(VISIBILITY_CFLAGS)

AM_CFLAGS += $(PTHREAD_CFLAGS)
