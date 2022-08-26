include $(top_srcdir)/Makefile.inc

TESTS_ENVIRONMENT = EXEEXT=${EXEEXT}

LDADD = $(LIB)/libodphelper.la $(LIB)/lib$(ODP_LIB_NAME).la

AM_CFLAGS += \
	-I$(srcdir) \
	-I$(top_srcdir)/example \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES)

if STATIC_APPS
AM_LDFLAGS += -static
endif

AM_LDFLAGS += $(PLAT_DEP_LIBS)
