ODP_MODULES = atomic \
	      barrier \
	      buffer \
	      chksum \
	      classification \
	      comp \
	      cpumask \
	      crypto \
	      dma \
	      errno \
	      event \
	      hash \
	      init \
	      ipsec \
	      lock \
	      queue \
	      packet \
	      pktio \
	      pool \
	      random \
	      scheduler \
	      stash \
	      std \
	      thread \
	      time \
	      timer \
	      traffic_mngr \
	      shmem \
	      system

SUBDIRS = $(ODP_MODULES)

include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation/api

TESTS = \
	atomic/atomic_main$(EXEEXT) \
	barrier/barrier_main$(EXEEXT) \
	buffer/buffer_main$(EXEEXT) \
	chksum/chksum_main$(EXEEXT) \
	classification/classification_main$(EXEEXT) \
	comp/comp_main$(EXEEXT) \
	cpumask/cpumask_main$(EXEEXT) \
	crypto/crypto_main$(EXEEXT) \
	dma/dma_main$(EXEEXT) \
	errno/errno_main$(EXEEXT) \
	event/event_main$(EXEEXT) \
	hash/hash_main$(EXEEXT) \
	init/init_defaults.sh \
	init/init_abort.sh \
	init/init_log.sh \
	init/init_log_thread.sh \
	init/init_num_thr.sh \
	init/init_feature_enabled.sh \
	init/init_feature_disabled.sh \
	init/init_test_param_init.sh \
	init/init_test_term_abnormal.sh \
	ipsec/ipsec_sync.sh \
	ipsec/ipsec_async.sh \
	ipsec/ipsec_inline_in.sh \
	ipsec/ipsec_inline_out.sh \
	lock/lock_main$(EXEEXT) \
	packet/packet_main$(EXEEXT) \
	pktio/pktio_main$(EXEEXT) \
	pool/pool_main$(EXEEXT) \
	queue/queue_main$(EXEEXT) \
	random/random_main$(EXEEXT) \
	scheduler/scheduler_main$(EXEEXT) \
	scheduler/scheduler_no_predef_groups$(EXEEXT) \
	stash/stash_main$(EXEEXT) \
	std/std_main$(EXEEXT) \
	thread/thread_main$(EXEEXT) \
	time/time_main$(EXEEXT) \
	timer/timer_main$(EXEEXT) \
	traffic_mngr/traffic_mngr_main$(EXEEXT) \
	shmem/shmem_main$(EXEEXT) \
	system/system_main$(EXEEXT)

TESTNAME = validation

TESTENV = tests-$(TESTNAME).env

test_DATA = $(TESTENV)

DISTCLEANFILES = $(TESTENV)
.PHONY: $(TESTENV)
$(TESTENV):
	echo "TESTS=\"$(TESTS)\""    > $@
	echo "$(TESTS_ENVIRONMENT)" >> $@
	echo "$(LOG_COMPILER)"      >> $@

.NOTPARALLEL:
