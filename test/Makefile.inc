include $(top_srcdir)/Makefile.inc
LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libodp.la
AM_CFLAGS += -I$(top_srcdir)/platform/@with_platform@/include/api -I$(top_srcdir)/platform/linux-generic/include/api -I$(top_srcdir)/include

AM_LDFLAGS += -L$(LIB)
