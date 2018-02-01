include $(top_srcdir)/Makefile.inc

AM_CFLAGS = \
        -I$(srcdir) \
        -I$(top_srcdir)/example \
        $(ODP_INCLUDES) \
        $(HELPER_INCLUDES) \
        $(PAPI_CFLAGS)

AM_LDFLAGS = $(PAPI_LIBS)

lib_LTLIBRARIES = $(LIB)/libinstrum.la

INSTRUM_SRC = \
		instrum.c \
		store.c \
		papi_cnt.c \
		init.c \
		instrum_common.h \
		sample.h \
		store.h \
		papi_cnt.h \
		init.h \
		pktio_direct.h \
		sched.h

if CODE_INSTRUM_SCHED
AM_CFLAGS += -DCODE_INSTRUM_SCHED
INSTRUM_SRC += sched.c
endif

if CODE_INSTRUM_PKTIO_DIRECT
AM_CFLAGS += -DCODE_INSTRUM_PKTIO_DIRECT
INSTRUM_SRC += pktio_direct.c
endif

__LIB__libinstrum_la_SOURCES = $(INSTRUM_SRC)
