include ../Makefile.inc

test_PROGRAMS = init_main
init_main_SOURCES = init_main.c

EXTRA_DIST = \
	init_defaults.sh \
	init_abort.sh \
	init_abort_fn_get.sh \
	init_log.sh \
	init_log_fn_get.sh \
	init_num_thr.sh \
	init_feature_enabled.sh \
	init_feature_disabled.sh \
	init_log_thread.sh \
	init_test_param_init.sh \
	init_test_term_abnormal.sh

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
