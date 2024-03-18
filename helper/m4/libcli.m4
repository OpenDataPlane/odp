# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Nokia
#

##########################################################################
# Set optional libcli path
##########################################################################
AC_ARG_WITH([libcli-path],
    [AS_HELP_STRING([--with-libcli-path=DIR],
        [path to libcli libs and headers [default=system]])],
    [libcli_path_given=yes
        LIBCLI_CPPFLAGS="-I$withval/include"
        LIBCLI_LIBS="-L$withval/lib"
        LIBCLI_RPATH="-R$withval/lib"],
    [])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
OLD_LIBS=$LIBS
CPPFLAGS="$LIBCLI_CPPFLAGS $CPPFLAGS"
LIBS="$LIBCLI_LIBS $LIBS"

#########################################################################
# If libcli is available, enable CLI helper
#########################################################################
helper_cli=no
AC_CHECK_HEADER(libcli.h,
    [AC_CHECK_LIB(cli, cli_init, [helper_cli=yes], [], [-lcrypt])],
    [AS_IF([test "x$libcli_path_given" = "xyes"],
        [AC_MSG_ERROR([libcli not found at the specified path (--with-libcli-path)])])])

AS_IF([test "x$helper_cli" != "xno"],
    [AC_DEFINE_UNQUOTED([ODPH_CLI], [1], [Define to 1 to enable CLI helper])
        LIBCLI_LIBS="$LIBCLI_RPATH $LIBCLI_LIBS -lcli -lcrypt"],
    [LIBCLI_CPPFLAGS=""
        LIBCLI_LIBS=""])

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS

AC_SUBST([LIBCLI_CPPFLAGS])
AC_SUBST([LIBCLI_LIBS])
