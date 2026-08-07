# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017 Linaro Limited
# Copyright (c) 2026 Nokia
#

# ODP_OPENSSL([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
#             [MIN-VERSION-HEX], [MIN-VERSION-STR])
# -----------------------------------------------------
# MIN-VERSION-HEX is compared against OPENSSL_VERSION_NUMBER and
# MIN-VERSION-STR is the matching human-readable version used in messages.
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
odp_openssl_err="OpenSSL not found"
AC_CHECK_HEADERS([openssl/des.h openssl/rand.h openssl/hmac.h openssl/evp.h], [],
		 [odp_openssl_ok=no])
AC_CACHE_CHECK([for EVP_EncryptInit in -lcrypto], [odp_cv_openssl_crypto],
[AC_LINK_IFELSE([AC_LANG_CALL([], [EVP_EncryptInit])],
	       [odp_cv_openssl_crypto=yes],
	       [odp_cv_openssl_crypto=no])])
if test "x$odp_cv_openssl_crypto" != "xyes" ; then
	odp_openssl_ok=no
fi

##########################################################################
# Check for a new enough OpenSSL version
##########################################################################
if test "x$odp_openssl_ok" = "xyes" ; then
	AC_MSG_CHECKING([for OpenSSL version >= $4])
	AC_PREPROC_IFELSE([AC_LANG_PROGRAM([[
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < $3
#error OpenSSL version is too old
#endif
]])],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])
	 odp_openssl_ok=no
	 odp_openssl_err="OpenSSL version $4 or later is required (use --without-openssl to build without OpenSSL)"])
fi

##########################################################################
# Finalize OpenSSL detection
##########################################################################
if test "x$odp_openssl_ok" = "xyes" ; then
	m4_default([$1], [:])
else
	OPENSSL_CPPFLAGS=""
	OPENSSL_LIBS=""
	OPENSSL_STATIC_LIBS=""
	m4_default([$2], [AC_MSG_FAILURE([$odp_openssl_err])])
fi

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS
]) # ODP_OPENSSL
