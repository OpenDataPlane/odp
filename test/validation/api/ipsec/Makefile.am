include ../Makefile.inc

noinst_LTLIBRARIES = libtestipsec.la
libtestipsec_la_SOURCES = \
	test_vectors.h \
	reass_test_vectors.h \
	ipsec_test_in.c \
	ipsec_test_out.c \
	ipsec.h \
	ipsec.c \
	reass_test_vectors.c

test_PROGRAMS = \
	ipsec_main

ipsec_main_SOURCES = \
	ipsec_main.c

PRELDADD += libtestipsec.la

EXTRA_DIST = \
	ipsec_sync.sh \
	ipsec_async.sh \
	ipsec_inline_in.sh \
	ipsec_inline_out.sh

dist_check_SCRIPTS = $(EXTRA_DIST)

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
