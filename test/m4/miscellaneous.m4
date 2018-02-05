##########################################################################
# Enable/disable test-cpp
##########################################################################
AC_ARG_ENABLE([test-cpp],
    [AS_HELP_STRING([--disable-test-cpp], [run basic test aginast cpp])],
    [test_cpp=$enableval],
    [test_cpp=yes])
AM_CONDITIONAL([test_cpp], [test x$test_cpp = xyes ])
