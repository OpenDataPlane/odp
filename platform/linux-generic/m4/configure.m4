ODP_IMPLEMENTATION_NAME="odp-linux"
ODP_LIB_NAME="odp-linux"

ODP_VISIBILITY
ODP_ATOMIC

ODP_PTHREAD
ODP_TIMER
m4_include([platform/linux-generic/m4/odp_cpu.m4])
m4_include([platform/linux-generic/m4/odp_event_validation.m4])
m4_include([platform/linux-generic/m4/odp_pcap.m4])
m4_include([platform/linux-generic/m4/odp_scheduler.m4])

AC_ARG_WITH([pcap],
	    [AS_HELP_STRING([--without-pcap],
			    [compile without PCAP [default=with] (linux-generic)])],
	    [],
	    [with_pcap=yes])
have_pcap=no
AS_IF([test "x$with_pcap" != xno],
      [ODP_PCAP([with_pcap=yes]‚[with_pcap=no])])
AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([ODP_PKTIO_PCAP], [test x$have_pcap = xyes])
])

m4_include([platform/linux-generic/m4/odp_libconfig.m4])
m4_include([platform/linux-generic/m4/odp_openssl.m4])
m4_include([platform/linux-generic/m4/odp_crypto.m4])
m4_include([platform/linux-generic/m4/odp_ipsec_mb.m4])
m4_include([platform/linux-generic/m4/odp_pcapng.m4])
m4_include([platform/linux-generic/m4/odp_dpdk.m4])
m4_include([platform/linux-generic/m4/odp_wfe.m4])
m4_include([platform/linux-generic/m4/odp_xdp.m4])
m4_include([platform/linux-generic/m4/odp_ml.m4])
ODP_EVENT_VALIDATION
ODP_SCHEDULER

AS_VAR_APPEND([PLAT_DEP_LIBS], ["${ATOMIC_LIBS} ${AARCH64CRYPTO_LIBS} ${LIBCONFIG_LIBS} ${OPENSSL_LIBS} ${IPSEC_MB_LIBS} ${DPDK_LIBS_LT} ${LIBCLI_LIBS} ${LIBXDP_LIBS} ${ORT_LIBS}"])

# Add text to the end of configure with platform specific settings.
# Make sure it's aligned same as other lines in configure.ac.
AS_VAR_APPEND([PLAT_CFG_TEXT], ["
	event_validation:       ${enable_event_validation}
	openssl:                ${with_openssl}
	openssl_rand:           ${openssl_rand}
	crypto:                 ${with_crypto}
	pcap:                   ${have_pcap}
	pcapng:                 ${have_pcapng}
	wfe_locks:              ${use_wfe_locks}
	ml_support:             ${ml_support}
	default_config_path:    ${default_config_path}"])

# Ignore Clang specific errors about fields with variable sized type not at the
# end of a struct. This style is used by e.g. odp_packet_hdr_t and
# odp_timeout_hdr_t.
ODP_CHECK_CFLAG([-Wno-error=gnu-variable-sized-type-not-at-end])

AC_CONFIG_COMMANDS_PRE([dnl
AM_CONDITIONAL([PLATFORM_IS_LINUX_GENERIC],
	       [test "${with_platform}" = "linux-generic"])
AC_CONFIG_FILES([platform/linux-generic/Makefile
		 platform/linux-generic/libodp-linux.pc
		 platform/linux-generic/dumpconfig/Makefile
		 platform/linux-generic/example/Makefile
		 platform/linux-generic/example/ml/Makefile
		 platform/linux-generic/test/Makefile
		 platform/linux-generic/test/example/Makefile
		 platform/linux-generic/test/example/classifier/Makefile
		 platform/linux-generic/test/example/generator/Makefile
		 platform/linux-generic/test/example/ipsec_api/Makefile
		 platform/linux-generic/test/example/ipsec_crypto/Makefile
		 platform/linux-generic/test/example/l2fwd_simple/Makefile
		 platform/linux-generic/test/example/l3fwd/Makefile
		 platform/linux-generic/test/example/packet/Makefile
		 platform/linux-generic/test/example/ping/Makefile
		 platform/linux-generic/test/example/simple_pipeline/Makefile
		 platform/linux-generic/test/example/switch/Makefile
		 platform/linux-generic/test/validation/api/shmem/Makefile
		 platform/linux-generic/test/validation/api/pktio/Makefile
		 platform/linux-generic/test/validation/api/ml/Makefile
		 platform/linux-generic/test/performance/Makefile
		 platform/linux-generic/test/performance/dmafwd/Makefile
		 platform/linux-generic/test/pktio_ipc/Makefile])
])
