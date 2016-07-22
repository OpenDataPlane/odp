##########################################################################
# Enable/disable test-cpp
##########################################################################
test_cpp=no
AC_ARG_ENABLE([test-cpp],
    [  --enable-test-cpp       run basic test aginast cpp],
    [if test "x$enableval" = "xyes"; then
        test_cpp=yes
    fi])
