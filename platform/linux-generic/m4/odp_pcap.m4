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
    ODP_CFLAGS="$AM_CFLAGS -DHAVE_PCAP"
    PCAP_LIBS="-lpcap"
fi

AC_SUBST([PCAP_LIBS])

AM_CONDITIONAL([HAVE_PCAP], [test $have_pcap = yes])
