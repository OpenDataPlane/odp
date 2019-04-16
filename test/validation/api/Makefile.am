ODP_MODULES = atomic \
	      barrier \
	      buffer \
	      chksum \
	      classification \
	      comp \
	      cpumask \
	      crypto \
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
	      std_clib \
	      thread \
	      time \
	      timer \
	      traffic_mngr \
	      shmem \
	      system

SUBDIRS = $(ODP_MODULES)

include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

TESTS = \
	atomic/atomic_main$(EXEEXT) \
	barrier/barrier_main$(EXEEXT) \
	buffer/buffer_main$(EXEEXT) \
	chksum/chksum_main$(EXEEXT) \
	classification/classification_main$(EXEEXT) \
	comp/comp_main$(EXEEXT) \
	cpumask/cpumask_main$(EXEEXT) \
	crypto/crypto_main$(EXEEXT) \
	errno/errno_main$(EXEEXT) \
	event/event_main$(EXEEXT) \
	hash/hash_main$(EXEEXT) \
	init/init_defaults$(EXEEXT) \
	init/init_abort$(EXEEXT) \
	init/init_log$(EXEEXT) \
	init/init_num_thr$(EXEEXT) \
	init/init_feature$(EXEEXT) \
	ipsec/ipsec_sync$(EXEEXT) \
	ipsec/ipsec_async$(EXEEXT) \
	ipsec/ipsec_inline_in$(EXEEXT) \
	ipsec/ipsec_inline_out$(EXEEXT) \
	lock/lock_main$(EXEEXT) \
	packet/packet_main$(EXEEXT) \
	pool/pool_main$(EXEEXT) \
	queue/queue_main$(EXEEXT) \
	random/random_main$(EXEEXT) \
	scheduler/scheduler_main$(EXEEXT) \
	std_clib/std_clib_main$(EXEEXT) \
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

if test_installdir
installcheck-local:
	$(DESTDIR)/$(testdir)/run-test.sh $(TESTNAME)
endif
