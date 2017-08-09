include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/common_plat/validation

ALL_API_VALIDATION_DIR = ${top_builddir}/test/common_plat/validation/api

SUBDIRS =

if test_vald
TESTS = validation/api/pktio/pktio_run.sh \
	$(ALL_API_VALIDATION_DIR)/atomic/atomic_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/barrier/barrier_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/buffer/buffer_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/classification/classification_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/cpumask/cpumask_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/crypto/crypto_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/errno/errno_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/hash/hash_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/init/init_main_ok$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/init/init_main_abort$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/init/init_main_log$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/lock/lock_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/packet/packet_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/pool/pool_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/queue/queue_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/random/random_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/scheduler/scheduler_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/std_clib/std_clib_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/thread/thread_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/time/time_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/timer/timer_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/traffic_mngr/traffic_mngr_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/shmem/shmem_main$(EXEEXT) \
	$(ALL_API_VALIDATION_DIR)/system/system_main$(EXEEXT)

SUBDIRS += validation/api/pktio
else
#performance tests refer to pktio_env
if test_perf
SUBDIRS += validation/api/pktio
endif
endif

dist_check_SCRIPTS = run-test tests-validation.env $(LOG_COMPILER)

test_SCRIPTS = $(dist_check_SCRIPTS)

tests-validation.env:
	echo "TESTS=\"$(TESTS)\""    > $@
	echo "$(TESTS_ENVIRONMENT)" >> $@
	echo "$(LOG_COMPILER)"      >> $@

if test_installdir
installcheck-local:
	$(DESTDIR)/$(testdir)/run-test
endif

