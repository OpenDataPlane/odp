##########################################################################
# Build and install example applications
##########################################################################
AC_ARG_WITH([examples],
	    [AS_HELP_STRING([--without-examples],
			    [don't build and install example applications])],
	    [],
	    [with_examples=yes])
AM_CONDITIONAL([WITH_EXAMPLES], [test x$with_examples != xno])

##########################################################################
# Test examples during 'make check'
##########################################################################
AC_ARG_ENABLE([test-example],
    [AS_HELP_STRING([--enable-test-example], [run basic test against examples])],
    [test_example=$enableval],
    [test_example=yes])
AM_CONDITIONAL([test_example], [test x$test_example = xyes ])

AC_CONFIG_FILES([example/classifier/Makefile
		 example/generator/Makefile
		 example/hello/Makefile
		 example/ipsec/Makefile
		 example/ipsec_api/Makefile
		 example/ipfragreass/Makefile
		 example/ipsec_offload/Makefile
		 example/l2fwd_simple/Makefile
		 example/l3fwd/Makefile
		 example/packet/Makefile
		 example/ping/Makefile
		 example/simple_pipeline/Makefile
		 example/switch/Makefile
		 example/sysinfo/Makefile
		 example/time/Makefile
		 example/timer/Makefile
		 example/traffic_mgmt/Makefile
		 example/Makefile])
