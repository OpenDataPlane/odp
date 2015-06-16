TESTS_ENVIRONMENT = TEST_DIR=${top_builddir}/test/validation

ODP_MODULES = pktio

if test_vald
TESTS = pktio/pktio_run
SUBDIRS = $(ODP_MODULES)
endif

#performance tests refer to pktio_env
if test_perf
SUBDIRS = pktio
endif
