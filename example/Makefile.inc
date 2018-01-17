include $(top_srcdir)/Makefile.inc

TESTS_ENVIRONMENT = EXEEXT=${EXEEXT}

LDADD = $(LIB)/libodp-linux.la $(LIB)/libodphelper.la $(DPDK_PMDS)
AM_CFLAGS = \
	-I$(srcdir) \
	-I$(top_srcdir)/example \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES)

AM_LDFLAGS = -L$(LIB) -static
