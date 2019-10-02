# ODP_PCAP([ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
# --------------------------------------------------
AC_DEFUN([ODP_PCAP],
[dnl
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
    AC_DEFINE([_ODP_PKTIO_PCAP], 1,
    	      [Define to 1 to enable pcap packet I/O support])
    PCAP_LIBS="-lpcap"
else
    PCAP_LIBS=""
fi

AC_SUBST([PCAP_LIBS])

if test "x$have_pcap" = "xyes" ; then
	m4_default([$1], [:])
else
	m4_default([$2], [:])
fi
]) # ODP_PCAP
