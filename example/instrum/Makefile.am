LIB   = $(top_builddir)/lib

AM_CFLAGS = \
        -I$(srcdir) \
        -I$(top_srcdir)/example \
        -I$(top_srcdir)/platform/@with_platform@/include \
        -I$(top_srcdir)/include/ \
        -I$(top_srcdir)/include/odp/arch/@ARCH_ABI@ \
        -I$(top_srcdir)/helper/include \
        -I$(top_builddir)/platform/@with_platform@/include \
        -I$(top_srcdir)/platform/@with_platform@/arch/@ARCH_DIR@ \
        -I$(top_builddir)/include \
        -I$(PAPI_PATH)/include

AM_LDFLAGS = -L$(PAPI_PATH)/lib -lpapi

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
