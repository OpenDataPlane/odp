include $(top_srcdir)/Makefile.inc

COMMON_DIR = $(top_builddir)/test/common

LIBODP = $(LIB)/libodphelper.la $(LIB)/libodp-linux.la

LIBCUNIT_COMMON = $(COMMON_DIR)/libcunit_common.la
LIBCPUMASK_COMMON = $(COMMON_DIR)/libcpumask_common.la
LIBTHRMASK_COMMON = $(COMMON_DIR)/libthrmask_common.la

#in the following line, the libs using the symbols should come before
#the libs containing them! The includer is given a chance to add things
#before libodp by setting PRELDADD before the inclusion.
LDADD = $(PRELDADD) $(LIBODP)
PRELDADD =

AM_CPPFLAGS = \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES) \
	-I$(top_srcdir)/test/common

# Do not link to DPDK twice in case of dynamic linking with ODP
if STATIC_APPS
LDADD += $(DPDK_LIBS_LT)
endif

AM_CFLAGS = $(CUNIT_CFLAGS)

if STATIC_APPS
AM_LDFLAGS = -L$(LIB) -static
else
AM_LDFLAGS =
endif

@VALGRIND_CHECK_RULES@

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform} \
		    EXEEXT=${EXEEXT}
