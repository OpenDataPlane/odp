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

AC_ARG_WITH([code-instrum-profile],
AS_HELP_STRING([--with-code-instrum-profile=all|scheduler|pktio_direct   set code instrumentation profile]),
    [code_instrum_profile="$withval"],
    [code_instrum_profile="all"])

AM_CONDITIONAL([CODE_INSTRUM_SCHED],[test $code_instrum_profile = "all" || test $code_instrum_profile = "scheduler"])
AM_CONDITIONAL([CODE_INSTRUM_PKTIO_DIRECT],[test $code_instrum_profile = "all" || test $code_instrum_profile = "pktio_direct"])

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
		 example/instrum/Makefile
		 example/Makefile])
