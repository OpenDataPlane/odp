# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017 Linaro Limited
#

# ODP_OPENSSL([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# -----------------------------------------------------
AC_DEFUN([ODP_OPENSSL],
[dnl
AC_ARG_VAR([OPENSSL_CPPFLAGS], [C preprocessor flags for OpenSSL])
AC_ARG_VAR([OPENSSL_LIBS], [linker flags for OpenSSL crypto library])
AC_ARG_VAR([OPENSSL_STATIC_LIBS], [static linker flags for OpenSSL crypto library])

##########################################################################
# Set optional OpenSSL path
##########################################################################
AC_ARG_WITH([openssl-path],
[AS_HELP_STRING([--with-openssl-path=DIR],
		[path to openssl libs and headers [default=system]])],
[OPENSSL_CPPFLAGS="-I$withval/include"
OPENSSL_LIBS="-L$withval/lib -lcrypto"],
[if test "x$ac_cv_env_OPENSSL_LIBS_set" != "xset" ; then
       OPENSSL_LIBS="-lcrypto"
fi])
if test "x$ac_cv_env_OPENSSL_STATIC_LIBS_set" != "xset" ; then
       OPENSSL_STATIC_LIBS="$OPENSSL_LIBS -ldl"
fi

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_CPPFLAGS=$CPPFLAGS
OLD_LIBS=$LIBS
CPPFLAGS="$OPENSSL_CPPFLAGS $CPPFLAGS"
LIBS="$OPENSSL_LIBS $LIBS"

##########################################################################
# Check for OpenSSL availability
##########################################################################
odp_openssl_ok=yes
AC_CHECK_HEADERS([openssl/des.h openssl/rand.h openssl/hmac.h openssl/evp.h], [],
		 [odp_openssl_ok=no])
AC_CACHE_CHECK([for EVP_EncryptInit in -lcrypto], [odp_cv_openssl_crypto],
[AC_LINK_IFELSE([AC_LANG_CALL([], [EVP_EncryptInit])],
	       [odp_cv_openssl_crypto=yes],
	       [odp_cv_openssl_crypto=no])])
if test "x$odp_cv_openssl_crypto" != "xyes" ; then
	odp_openssl_ok=no
fi

if test "x$odp_openssl_ok" = "xyes" ; then
	m4_default([$1], [:])
else
	OPENSSL_CPPFLAGS=""
	OPENSSL_LIBS=""
	OPENSSL_STATIC_LIBS=""
	m4_default([$2], [AC_MSG_FAILURE([OpenSSL not found])])
fi

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS
]) # ODP_OPENSSL
