include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

if WITH_OPENSSL
TESTS_ENVIRONMENT += WITH_OPENSSL=1
else
TESTS_ENVIRONMENT += WITH_OPENSSL=0
endif

SUBDIRS =

if test_vald
TESTS = validation/api/pktio/pktio_run.sh \
	validation/api/pktio/pktio_run_tap.sh \
	validation/api/shmem/shmem_linux$(EXEEXT) \
	ipsec/ipsec_api_example.sh \
	ipsec/ipsec_crypto_example.sh

dist_check_SCRIPTS = ipsec/ipsec_api_example.sh \
		     ipsec/ipsec_crypto_example.sh

test_SCRIPTS = $(dist_check_SCRIPTS)

SUBDIRS += validation/api/pktio\
	  validation/api/shmem\
	  pktio_ipc

if ODP_PKTIO_PCAP
TESTS += validation/api/pktio/pktio_run_pcap.sh
endif
if netmap_support
TESTS += validation/api/pktio/pktio_run_netmap.sh
endif
if PKTIO_DPDK
TESTS += validation/api/pktio/pktio_run_dpdk.sh
endif
TESTS += pktio_ipc/pktio_ipc_run.sh
SUBDIRS += pktio_ipc
else
#performance tests refer to pktio_env
if test_perf
SUBDIRS += validation/api/pktio
endif
endif

TEST_EXTENSIONS = .sh

TESTNAME = linux-generic

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
