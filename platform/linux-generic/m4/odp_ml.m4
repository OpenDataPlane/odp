##########################################################################
# Onnxruntime library path and name
##########################################################################
# Optional configure parameter for a non-standard install prefix of onnxruntime
AC_ARG_WITH([ort-path],
        [AS_HELP_STRING([--with-ort-path=DIR],
		[path to onnxruntime libs and headers [default=system]])],
        [ort_path_given=yes
                ORT_CPPFLAGS="-I$withval/include"
                ORT_LIBS="-L$withval/lib"
                ORT_RPATH="-R$withval/lib"],
        [])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
OLD_LIBS=$LIBS
CPPFLAGS="$ORT_CPPFLAGS $CPPFLAGS"
LIBS="$ORT_LIBS $LIBS"

#########################################################################
# If ort is available, enable ML API
#########################################################################
ml_support=no
AC_CHECK_HEADERS([onnxruntime_c_api.h],
        [AC_CHECK_LIB(onnxruntime, OrtGetApiBase, [ml_support=yes], [], [])],
        [AS_IF([test "x$ort_path_given" = "xyes"],
                [AC_MSG_ERROR([ort not found at the specified path (--with-ort-path)])])])

AS_IF([test "x$ml_support" != "xno"],
    [ORT_LIBS="$ORT_RPATH $ORT_LIBS -lonnxruntime -lm"],
    [ORT_CPPFLAGS="" ORT_LIBS="-lm"])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([WITH_ML], [test x$ml_support = xyes ])
])

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS

AC_SUBST([ORT_CPPFLAGS])
AC_SUBST([ORT_LIBS])
