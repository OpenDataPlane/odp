##########################################################################
# Enable/disable test-perf
##########################################################################
test_perf=no
AC_ARG_ENABLE([test-perf],
    [  --enable-test-perf      run test in test/performance],
    [if test "x$enableval" = "xyes"; then
        test_perf=yes
    fi])
