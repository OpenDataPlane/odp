TESTS_ENVIRONMENT = TEST_DIR=${top_builddir}/test/validation

ODP_MODULES = pktio

if test_vald
TESTS = pktio/pktio_run \
	${top_builddir}/test/validation/classification/classification_main$(EXEEXT) \
	${top_builddir}/test/validation/crypto/crypto_main \
	${top_builddir}/test/validation/random/random_main$(EXEEXT) \
	${top_builddir}/test/validation/system/system_main$(EXEEXT)

SUBDIRS = $(ODP_MODULES)
endif

#performance tests refer to pktio_env
if test_perf
SUBDIRS = pktio
endif
