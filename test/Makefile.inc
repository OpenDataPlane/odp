include $(top_srcdir)/Makefile.inc
include $(top_srcdir)/platform/@with_platform@/Makefile.inc
LIB   = $(top_builddir)/lib
LDADD = $(LIB)/libodp.la
INCFLAGS = -I$(srcdir) \
	-I$(top_srcdir)/test \
	-I$(top_srcdir)/platform/@with_platform@/include \
	-I$(top_srcdir)/platform/linux-generic/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/helper/include
AM_CFLAGS += $(INCFLAGS)
AM_CXXFLAGS = $(INCFLAGS)

AM_LDFLAGS += -L$(LIB)

@VALGRIND_CHECK_RULES@
valgrind_tools = memcheck drd sgcheck
