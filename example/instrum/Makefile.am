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

noinst_HEADERS = \
		$(srcdir)/instrum_common.h \
		$(srcdir)/sample.h \
		$(srcdir)/store.h \
		$(srcdir)/papi_cnt.h \
		$(srcdir)/init.h \
		$(srcdir)/drv.h \
		$(srcdir)/sched.h

__LIB__libinstrum_la_SOURCES = \
		instrum.c \
		store.c \
		papi_cnt.c \
		init.c \
		drv.c \
		sched.c
