# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018 Linaro Limited
#

##########################################################################
# Enable PCAPNG support
##########################################################################
have_pcapng=no
pcapng_support=0

AC_ARG_ENABLE([pcapng-support],
	[AS_HELP_STRING([--enable-pcapng-support],
	[enable experimental tcpdump for pktios [default=disabled] (linux-generic)])],
	have_pcapng=$enableval
    [if test x$enableval = xyes; then
        pcapng_support=1
    fi])

AC_DEFINE_UNQUOTED([_ODP_PCAPNG], [$pcapng_support],
	[Define to 1 to enable pcapng support])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([have_pcapng], [test x$have_pcapng = xyes])
])
