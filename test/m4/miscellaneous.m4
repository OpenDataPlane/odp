##########################################################################
# Enable/disable test-cpp
##########################################################################
AC_ARG_ENABLE([test-cpp],
    [AS_HELP_STRING([--disable-test-cpp], [run basic test against cpp])],
    [test_cpp=$enableval],
    [test_cpp=check])

if test "x$test_cpp" != "xno" ; then
    AC_CACHE_CHECK([if C++ compiler works], [odp_cv_cxx_works],
      [AC_LANG_PUSH([C++])
       AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])], [odp_cv_cxx_works=yes],
                         [odp_cv_cxx_works=no])
       AC_LANG_POP([C++])])
    AS_IF([test "x$test_cpp$odp_cv_cxx_works" = "xyesno"],
          [AC_MSG_FAILURE([C++ compiler test failed])],
          [test "x$test_cpp$odp_cv_cxx_works" = "xcheckno"],
          [AC_MSG_NOTICE([disabling C++ test]) ; test_cpp=no],
          [test_cpp=yes])
fi

AM_CONDITIONAL([test_cpp], [test x$test_cpp = xyes ])
