#########################################################################
# Check for libpcap availability
#########################################################################
have_pcap=no
AC_CHECK_HEADER(pcap/pcap.h,
    [AC_CHECK_HEADER(pcap/bpf.h,
        [AC_CHECK_LIB(pcap, pcap_open_offline, have_pcap=yes, [])],
    [])],
[])

if test "$have_pcap" = "yes"; then
    AC_DEFINE([HAVE_PCAP], 1, [Define to 1 if you have pcap library])
    PCAP_LIBS="-lpcap"
fi

AC_SUBST([PCAP_LIBS])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([HAVE_PCAP], [test x$have_pcap = xyes])
])
