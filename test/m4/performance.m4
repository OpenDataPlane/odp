##########################################################################
# Enable/disable test-perf
##########################################################################
AC_ARG_ENABLE([test-perf],
    [AS_HELP_STRING([--enable-test-perf],
                    [run test in test/performance [default=enabled]])],
    [test_perf=$enableval],
    [test_perf=yes])
AM_CONDITIONAL([test_perf], [test x$test_perf = xyes ])

##########################################################################
# Enable/disable icache perf test
##########################################################################
AC_ARG_ENABLE([icache-perf-test],
    [AS_HELP_STRING([--enable-icache-perf-test],
                    [enable odp_icache_perf in build and test [default=disabled]])],
    [icache_perf_test=$enableval],
    [icache_perf_test=no])
AM_CONDITIONAL([icache_perf_test], [test x$icache_perf_test = xyes ])
