##########################################################################
# Enable/disable test-perf-proc
##########################################################################
test_perf_proc=no
AC_ARG_ENABLE([test-perf-proc],
    [  --enable-test-perf-proc      run test in test/performance in process mode],
    [if test "x$enableval" = "xyes"; then
        test_perf_proc=yes
    fi])
