##########################################################################
# Enable/disable test-helper
##########################################################################
test_helper=no
AC_ARG_ENABLE([test-helper],
    [  --enable-test-helper      run test in helper/test],
    [if test "x$enableval" = "xyes"; then
        test_helper=yes
    fi])
