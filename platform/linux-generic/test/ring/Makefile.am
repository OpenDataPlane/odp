# ring test uses internal symbols from libodp-linux which are not available
# when linking test with libodp-linux.so
if STATIC_APPS

include $(top_srcdir)/test/Makefile.inc

test_PROGRAMS = ring_main
ring_main_SOURCES = \
		    ring_main.c \
		    ring_suites.c ring_suites.h \
		    ring_basic.c ring_stress.c

TESTS = ring_main$(EXEEXT)

PRELDADD += $(LIBCUNIT_COMMON)

AM_CPPFLAGS += -I$(top_srcdir)/platform/linux-generic/include

TESTNAME = linux-generic-ring

TESTENV = tests-$(TESTNAME).env

test_DATA = $(TESTENV)

DISTCLEANFILES = $(TESTENV)
.PHONY: $(TESTENV)
$(TESTENV):
	echo "TESTS=\"$(TESTS)\""    > $@
	echo "$(TESTS_ENVIRONMENT)" >> $@
	echo "$(LOG_COMPILER)"      >> $@

if test_installdir
installcheck-local:
	$(DESTDIR)/$(testdir)/run-test.sh $(TESTNAME)
endif
endif
