# ODP_CRYPTO
# ----------
# Select default crypto implementation
AC_ARG_ENABLE([crypto-default],
             [AS_HELP_STRING([--enable-crypto-default],
                             [choose default crypto implementation [openssl/armv8crypto/null] (linux-generic)])],
             [default_crypto=$enableval], [default_crypto=openssl])
AS_IF([test "x$default_crypto" != "xopenssl" -a "x$default_crypto" != "xarmv8crypto" -a "x$default_crypto" != "xnull"],
      [AC_MSG_ERROR([Invalid crypto implementation name])])

##########################################################################
# OpenSSL implementation
##########################################################################
AS_IF([test "x$default_crypto" == "xopenssl"],
      [ODP_OPENSSL
       have_openssl=1], [have_openssl=0])
AM_CONDITIONAL([WITH_OPENSSL], [test "x$default_crypto" == "xopenssl"])
AC_DEFINE_UNQUOTED([_ODP_OPENSSL], [$have_openssl],
         [Set crypto-default to openssl to enable OpenSSL crypto])

##########################################################################
# ARMv8 Crypto library implementation
##########################################################################
AS_IF([test "x$default_crypto" == "xarmv8crypto"],
      [PKG_CHECK_MODULES([AARCH64CRYPTO], [libAArch64crypto])
       AARCH64CRYPTO_PKG=", libAArch64crypto"
       AC_SUBST([AARCH64CRYPTO_PKG])])
AM_CONDITIONAL([WITH_ARMV8_CRYPTO], [test "x$default_crypto" == "xarmv8crypto"])

##########################################################################
# Null implementation
##########################################################################
AS_IF([test "x$default_crypto" == "xnull"],
      [AC_MSG_WARN([Using null crypto. Strong cryptography is not available!])])
