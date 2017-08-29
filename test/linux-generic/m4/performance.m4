##########################################################################
# Enable/disable test-perf-proc
##########################################################################
AC_ARG_ENABLE([test-perf-proc],
    [AS_HELP_STRING([--enable-test-perf-proc], [run test in test/performance in process mode])],
    [test_perf_proc=$enableval],
    [test_perf_proc=yes])
AM_CONDITIONAL([test_perf_proc], [test x$test_perf_proc = xyes ])
