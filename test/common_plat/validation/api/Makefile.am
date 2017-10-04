ODP_MODULES = atomic \
	      barrier \
	      buffer \
	      classification \
	      cpumask \
	      crypto \
	      errno \
	      hash \
	      init \
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
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/common_plat/validation

TESTS = \
	atomic/atomic_main$(EXEEXT) \
	barrier/barrier_main$(EXEEXT) \
	buffer/buffer_main$(EXEEXT) \
	classification/classification_main$(EXEEXT) \
	cpumask/cpumask_main$(EXEEXT) \
	crypto/crypto_main$(EXEEXT) \
	errno/errno_main$(EXEEXT) \
	hash/hash_main$(EXEEXT) \
	init/init_main_ok$(EXEEXT) \
	init/init_main_abort$(EXEEXT) \
	init/init_main_log$(EXEEXT) \
	lock/lock_main$(EXEEXT) \
	packet/packet_main$(EXEEXT) \
	pool/pool_main$(EXEEXT) \
	queue/queue_main$(EXEEXT) \
	random/random_main$(EXEEXT) \
	scheduler/scheduler_main$(EXEEXT) \
	std_clib/std_clib_main$(EXEEXT) \
	thread/thread_main$(EXEEXT) \
	time/time.sh \
	timer/timer_main$(EXEEXT) \
	traffic_mngr/traffic_mngr.sh \
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
