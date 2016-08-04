m4_include([test/linux-generic/m4/performance.m4])

AC_CONFIG_FILES([test/linux-generic/Makefile
		 test/linux-generic/validation/api/shmem/Makefile
		 test/linux-generic/validation/api/pktio/Makefile
		 test/linux-generic/pktio_ipc/Makefile
		 test/linux-generic/ring/Makefile
		 test/linux-generic/performance/Makefile])
