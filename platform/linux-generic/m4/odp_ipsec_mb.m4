# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 ARM Limited
#

#########################################################################
# Check for libIPSec_MB availability
#########################################################################
ipsecmb_support=no
AC_CHECK_HEADERS([ipsec-mb.h],
        [AC_CHECK_LIB([IPSec_MB], [init_mb_mgr_auto], [ipsecmb_support=yes],
                [ipsecmb_support=no])],
        [ipsecmb_support=no])

AS_IF([test "x$with_crypto" = "xipsecmb" -a "x$ipsecmb_support" = "xno"],
      [AC_MSG_ERROR([IPSec MB library not found on this platform])])

if test "x$with_crypto" = "xipsecmb"; then
        IPSEC_MB_LIBS="-lIPSec_MB"
else
        IPSEC_MB_LIBS=""
fi

AC_SUBST([IPSEC_MB_LIBS])
