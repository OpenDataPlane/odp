include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

if WITH_OPENSSL_CRYPTO
TESTS_ENVIRONMENT += WITH_OPENSSL_CRYPTO=1
else
TESTS_ENVIRONMENT += WITH_OPENSSL_CRYPTO=0
endif

SUBDIRS =
TESTS =

if test_vald
TESTS += validation/api/pktio/pktio_run.sh \
	 validation/api/pktio/pktio_run_tap.sh \
	 validation/api/shmem/shmem_linux$(EXEEXT)

SUBDIRS += validation/api/pktio\
	  validation/api/shmem\
	  pktio_ipc \
	  example

if ODP_PKTIO_PCAP
TESTS += validation/api/pktio/pktio_run_pcap.sh
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
