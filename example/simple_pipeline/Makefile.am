include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_simple_pipeline

odp_simple_pipeline_SOURCES = odp_simple_pipeline.c

if test_example
if ODP_PKTIO_PCAP
TESTS = simple_pipeline_run.sh
endif
endif
EXTRA_DIST = simple_pipeline_run.sh udp64.pcap

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(EXTRA_DIST); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
