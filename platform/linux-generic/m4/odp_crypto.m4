# ODP_CRYPTO
# ----------
# Select default crypto implementation
AC_ARG_WITH([crypto],
            [AS_HELP_STRING([--with-crypto],
                            [Choose crypto implementation (openssl/armv8crypto/null)]
                            [[default=openssl] (linux-generic)])],
            [], [with_crypto=openssl])

# Default to OpenSSL implementation if crypto is enabled
AS_IF([test "x$with_crypto" = "xyes"], [with_crypto=openssl])

# Default to Null implementation if crypto is disabled
AS_IF([test "x$with_crypto" = "xno"], [with_crypto=null])
AS_IF([test "x$with_crypto" = "xopenssl" -a "x$with_openssl" = "xno"], [with_crypto=null])

AS_IF([test "x$with_crypto" != "xopenssl" -a "x$with_crypto" != "xarmv8crypto" -a "x$with_crypto" != "xipsecmb" -a "x$with_crypto" != "xnull"],
      [AC_MSG_ERROR([Invalid crypto implementation name])])

##########################################################################
# OpenSSL implementation
##########################################################################
AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([WITH_OPENSSL_CRYPTO], [test "x$with_crypto" == "xopenssl"])
])

##########################################################################
# ARMv8 Crypto library implementation
##########################################################################
AS_IF([test "x$with_crypto" == "xarmv8crypto"],
      [PKG_CHECK_MODULES([AARCH64CRYPTO], [libAArch64crypto])
       AARCH64CRYPTO_PKG=", libAArch64crypto"
       AC_SUBST([AARCH64CRYPTO_PKG])])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([WITH_ARMV8_CRYPTO], [test "x$with_crypto" == "xarmv8crypto"])
])

##########################################################################
# Multi-buffer IPSec library implementation
##########################################################################
ipsecmb_support=0
AS_IF([test "x$with_crypto" == "xipsecmb"],
      [AC_CHECK_HEADERS([ipsec-mb.h],
                        [ipsecmb_support=1],
                        [AC_MSG_ERROR([IPSec MB library not supported on this platform])])])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([WITH_IPSECMB_CRYPTO], [test "x$with_crypto" == "xipsecmb"])
])

##########################################################################
# Null implementation
##########################################################################
AS_IF([test "x$with_crypto" == "xnull"],
      [AC_MSG_WARN([Using null crypto. Strong cryptography is not available])])
