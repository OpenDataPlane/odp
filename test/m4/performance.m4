##########################################################################
# Enable/disable test-perf
##########################################################################
AC_ARG_ENABLE([test-perf],
    [AS_HELP_STRING([--enable-test-perf], [run test in test/performance])],
    [test_perf=$enableval],
    [test_perf=yes])
AM_CONDITIONAL([test_perf], [test x$test_perf = xyes ])
