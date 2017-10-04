include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/common_plat/validation

SUBDIRS = performance

if test_vald
TESTS = validation/api/pktio/pktio_run.sh \
	validation/api/pktio/pktio_run_tap.sh \
	validation/api/shmem/shmem_linux \
	ring/ring_main$(EXEEXT)

SUBDIRS += validation/api/pktio\
	   validation/api/shmem\
	   mmap_vlan_ins\
	   pktio_ipc\
	   ring

if HAVE_PCAP
TESTS += validation/api/pktio/pktio_run_pcap.sh

TESTS +=   mmap_vlan_ins/mmap_vlan_ins.sh
SUBDIRS += mmap_vlan_ins
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
