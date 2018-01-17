include $(top_srcdir)/Makefile.inc

#in the following line, the libs using the symbols should come before
#the libs containing them! The includer is given a chance to add things
#before libodp by setting PRE_LDADD before the inclusion.
LDADD = $(PRE_LDADD) $(LIB)/libodphelper.la $(LIB)/libodp-linux.la $(DPDK_PMDS)

AM_CPPFLAGS = \
	$(ODP_INCLUDES) \
	$(HELPER_INCLUDES) \
	-I$(top_srcdir)/test/common
AM_CFLAGS = $(CUNIT_CFLAGS)

AM_LDFLAGS = -L$(LIB) -static

@VALGRIND_CHECK_RULES@

TESTS_ENVIRONMENT = ODP_PLATFORM=${with_platform} \
		    EXEEXT=${EXEEXT} \
		    ODP_SYSCONFIG_FILE=none
