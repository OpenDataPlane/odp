##########################################################################
# Enable/disable test-example
##########################################################################
AC_ARG_ENABLE([test-example],
    [AS_HELP_STRING([--enable-test-example], [run basic test against examples])],
    [test_example=$enableval],
    [test_example=yes])
AM_CONDITIONAL([test_example], [test x$test_example = xyes ])

code_instrumentation=no
AC_ARG_ENABLE([code-instrum],
    [AS_HELP_STRING([--enable-code-instrum], [enable code instrumentation support])],
    [if test x$enableval = xyes; then
        code_instrumentation=yes
        PKG_CHECK_MODULES([PAPI], [papi-5])
    fi])

AM_CONDITIONAL([CODE_INSTRUM], [test x$code_instrumentation = xyes ])

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
		 example/switch/Makefile
		 example/time/Makefile
		 example/timer/Makefile
		 example/traffic_mgmt/Makefile
		 example/Makefile])
