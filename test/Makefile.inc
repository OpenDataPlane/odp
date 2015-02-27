include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc
LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libodp.la
AM_CFLAGS += \
	-I$(srcdir) \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/platform/@with_platform@/include/api \
	-I$(top_srcdir)/platform/linux-generic/include/api \
	-I$(top_srcdir)/helper/include

AM_LDFLAGS += -L$(LIB)
