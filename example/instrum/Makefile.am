include $(top_srcdir)/Makefile.inc

AM_CFLAGS = \
        -I$(srcdir) \
        -I$(top_srcdir)/example \
        $(ODP_INCLUDES) \
        $(HELPER_INCLUDES) \
        $(PAPI_CFLAGS)

AM_LDFLAGS = $(PAPI_LIBS)

lib_LTLIBRARIES = $(LIB)/libinstrum.la

__LIB__libinstrum_la_SOURCES = \
		instrum.c
