##########################################################################
# Set optional OpenSSL path
##########################################################################
AC_ARG_WITH([openssl-path],
AC_HELP_STRING([--with-openssl-path=DIR path to openssl libs and headers],
               [(or in the default path if not specified).]),
    [OPENSSL_PATH=$withval
    OPENSSL_CPPFLAGS="-I$OPENSSL_PATH/include"
    OPENSSL_LIBS="-L$OPENSSL_PATH/lib"
    ],[])

##########################################################################
# Save and set temporary compilation flags
##########################################################################
OLD_LDFLAGS=$LDFLAGS
OLD_CPPFLAGS=$CPPFLAGS
LIBS="$OPENSSL_LIBS $LIBS"
CPPFLAGS="$OPENSSL_CPPFLAGS $CPPFLAGS"

##########################################################################
# Check for OpenSSL availability
##########################################################################
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [OPENSSL_LIBS="$OPENSSL_LIBS -lcrypto"
					   OPENSSL_STATIC_LIBS="$OPENSSL_LIBS -ldl"],
             [AC_MSG_FAILURE([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/des.h openssl/rand.h openssl/hmac.h openssl/evp.h], [],
             [AC_MSG_ERROR([OpenSSL headers required])])

AC_SUBST([OPENSSL_CPPFLAGS])
AC_SUBST([OPENSSL_LIBS])
AC_SUBST([OPENSSL_STATIC_LIBS])

##########################################################################
# Restore old saved variables
##########################################################################
LIBS=$OLD_LIBS
CPPFLAGS=$OLD_CPPFLAGS
