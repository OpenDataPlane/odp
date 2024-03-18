# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015 Linaro Limited
#

##########################################################################
# Enable/disable usage of OpenSSL library
##########################################################################
AC_ARG_WITH([openssl],
	    [AS_HELP_STRING([--without-openssl],
			    [compile without OpenSSL (may result in disabled crypto and random support)]
			    [[default=with] (linux-generic)])],
	    [],
	    [with_openssl=yes])
AS_IF([test "$with_openssl" != "no"],
      [ODP_OPENSSL
       have_openssl=1], [have_openssl=0])
AM_CONDITIONAL([WITH_OPENSSL], [test x$with_openssl != xno])
AC_DEFINE_UNQUOTED([_ODP_OPENSSL], [$have_openssl],
	  [Define to 1 to enable OpenSSL support])

##########################################################################
# Enable/disable usage of OpenSSL for random data
##########################################################################
have_openssl_rand=1
AC_ARG_ENABLE([openssl-rand],
	[AS_HELP_STRING([--disable-openssl-rand],
			[disable OpenSSL random data (use arch-specific instead)]
			[[default=enabled] (linux-generic)])],
	[if test "x$enableval" = "xno"; then
		have_openssl_rand=0
	fi])

AS_IF([test "$have_openssl" != "1"], [have_openssl_rand=0])
AS_IF([test "$have_openssl_rand" = "1"], [openssl_rand=yes], [openssl_rand=no])

AC_DEFINE_UNQUOTED([_ODP_OPENSSL_RAND], [$have_openssl_rand],
	  [Define to 1 to enable OpenSSL support])
