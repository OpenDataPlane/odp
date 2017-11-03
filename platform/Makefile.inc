LIB   = $(top_builddir)/lib

VPATH = $(srcdir) $(builddir)

AM_LDFLAGS = -version-number '$(ODP_LIBSO_VERSION)'

AM_CFLAGS = "-DGIT_HASH=$(VERSION)"
AM_CFLAGS += $(VISIBILITY_CFLAGS)

AM_CFLAGS += @PTHREAD_CFLAGS@
