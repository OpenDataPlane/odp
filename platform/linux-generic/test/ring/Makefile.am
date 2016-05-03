include $(top_srcdir)/test/validation/Makefile.inc

AM_CFLAGS += -I$(srcdir)/common
AM_CFLAGS += -I$(top_srcdir)/test/validation/common
AM_LDFLAGS += -static

COMPILE_ONLY =

TESTSCRIPTS =

EXECUTABLES = ringtest$(EXEEXT)

test_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

ringtest_SOURCES = ringtest.c
ringtest_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)
