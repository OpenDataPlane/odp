##########################################################################
# Set optional zlib path
##########################################################################
AC_ARG_WITH([zlib-path],
AC_HELP_STRING([--with-zlib-path=DIR path to zlib libs and headers],
               [(or in the default path if not specified).]),
    [ZLIB_PATH=$withval
    AM_CPPFLAGS="$AM_CPPFLAGS -I$ZLIB_PATH"
    AM_LDFLAGS="$AM_LDFLAGS -L$ZLIB_PATH"
    ],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
CPPFLAGS="$AM_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for ZLIB availability
##########################################################################
AC_CHECK_LIB([z], [deflateInit_],[ZLIB_LIBS="-lz"],
             [AC_MSG_FAILURE([Zlib libraries required])],)


AC_CHECK_HEADERS([zlib.h], [],
             [AC_MSG_ERROR([ZLib headers required])])

AC_SUBST([ZLIB_LIBS])
##########################################################################
# Restore old saved variables
##########################################################################
LDFLAGS=$OLD_LDFLAGS
CPPFLAGS=$OLD_CPPFLAGS
