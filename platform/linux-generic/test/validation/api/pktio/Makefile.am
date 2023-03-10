dist_check_SCRIPTS = pktio_env \
		     pktio_run.sh \
		     pktio_run_tap.sh

if ODP_PKTIO_PCAP
dist_check_SCRIPTS += pktio_run_pcap.sh
endif
if PKTIO_DPDK
dist_check_SCRIPTS += pktio_run_dpdk.sh
endif

test_SCRIPTS = $(dist_check_SCRIPTS)

# If building out-of-tree, make check will not copy the scripts and data to the
# $(builddir) assuming that all commands are run locally. However this prevents
# running tests on a remote target using LOG_COMPILER.
# So copy all script and data files explicitly here.
all-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			if [ -e $(srcdir)/$$f ]; then \
				mkdir -p $(builddir)/$$(dirname $$f); \
				cp -f $(srcdir)/$$f $(builddir)/$$f; \
			fi \
		done \
	fi
clean-local:
	if [ "x$(srcdir)" != "x$(builddir)" ]; then \
		for f in $(dist_check_SCRIPTS); do \
			rm -f $(builddir)/$$f; \
		done \
	fi
