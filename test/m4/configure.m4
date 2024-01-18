##########################################################################
# Build and install test applications
##########################################################################
AC_ARG_WITH([tests],
	    [AS_HELP_STRING([--without-tests],
			    [don't build and install test applications]
			    [[default=with]])],
	    [],
	    [with_tests=yes])
AM_CONDITIONAL([WITH_TESTS], [test x$with_tests != xno])

m4_include([test/m4/miscellaneous.m4])
m4_include([test/m4/performance.m4])
m4_include([test/m4/validation.m4])

AC_CONFIG_FILES([test/common/Makefile
		 test/miscellaneous/Makefile
		 test/performance/Makefile
		 test/validation/Makefile
		 test/validation/api/align/Makefile
		 test/validation/api/atomic/Makefile
		 test/validation/api/barrier/Makefile
		 test/validation/api/buffer/Makefile
		 test/validation/api/byteorder/Makefile
		 test/validation/api/chksum/Makefile
		 test/validation/api/classification/Makefile
		 test/validation/api/comp/Makefile
		 test/validation/api/cpumask/Makefile
		 test/validation/api/crypto/Makefile
		 test/validation/api/dma/Makefile
		 test/validation/api/errno/Makefile
		 test/validation/api/event/Makefile
		 test/validation/api/hash/Makefile
		 test/validation/api/hints/Makefile
		 test/validation/api/init/Makefile
		 test/validation/api/ipsec/Makefile
		 test/validation/api/lock/Makefile
		 test/validation/api/Makefile
		 test/validation/api/packet/Makefile
		 test/validation/api/pktio/Makefile
		 test/validation/api/pool/Makefile
		 test/validation/api/queue/Makefile
		 test/validation/api/random/Makefile
		 test/validation/api/scheduler/Makefile
		 test/validation/api/shmem/Makefile
		 test/validation/api/stash/Makefile
		 test/validation/api/std/Makefile
		 test/validation/api/system/Makefile
		 test/validation/api/thread/Makefile
		 test/validation/api/time/Makefile
		 test/validation/api/timer/Makefile
		 test/validation/api/traffic_mngr/Makefile])
