# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2016 Linaro Limited
#

##########################################################################
# Enable DPDK support
##########################################################################
pktio_dpdk_min_version=22.11.0
pktio_dpdk_support=no

AC_ARG_ENABLE([dpdk],
	      [AS_HELP_STRING([--enable-dpdk],
			      [enable DPDK support for Packet I/O [default=disabled] (linux-generic)])],
	      [pktio_dpdk_support=$enableval])

##########################################################################
# Use shared DPDK library
##########################################################################
dpdk_shared=no
AC_ARG_ENABLE([dpdk-shared],
    [AS_HELP_STRING([--enable-dpdk-shared],
                    [use shared DPDK library [default=disabled] (linux-generic)])],
    [if test x$enableval = xyes; then
        dpdk_shared=yes
    fi])

##########################################################################
# Enable zero-copy DPDK pktio
##########################################################################
zero_copy=0
AC_ARG_ENABLE([dpdk-zero-copy],
    [AS_HELP_STRING([--enable-dpdk-zero-copy],
                    [enable experimental zero-copy DPDK pktio mode [default=disabled] (linux-generic)])],
    [if test x$enableval = xyes; then
        pktio_dpdk_support=yes
        zero_copy=1
    fi])

##########################################################################
# Check for DPDK availability
#
# DPDK pmd drivers are not linked unless the --whole-archive option is
# used. No spaces are allowed between the --whole-archive flags.
##########################################################################
if test x$pktio_dpdk_support = xyes
then
    ODP_DPDK([$pktio_dpdk_min_version], [$dpdk_shared], [],
	     [AC_MSG_FAILURE([can't find DPDK])])

    case "${host}" in
      i?86* | x86*)
	DPDK_CFLAGS="${DPDK_CFLAGS} -msse4.2"
      ;;
    esac

    ODP_CHECK_CFLAG([-Wno-error=cast-align])
    AC_DEFINE([_ODP_PKTIO_DPDK], [1],
	      [Define to 1 to enable DPDK packet I/O support])
    AC_DEFINE_UNQUOTED([_ODP_DPDK_ZERO_COPY], [$zero_copy],
	      [Define to 1 to enable DPDK zero copy support])
else
    pktio_dpdk_support=no
fi

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PKTIO_DPDK], [test x$pktio_dpdk_support = xyes ])
])
