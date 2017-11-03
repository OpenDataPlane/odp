dist_check_SCRIPTS = pktio_env \
		     pktio_run.sh \
		     pktio_run_tap.sh

if HAVE_PCAP
dist_check_SCRIPTS += pktio_run_pcap.sh
endif
if netmap_support
dist_check_SCRIPTS += pktio_run_netmap.sh
endif
if PKTIO_DPDK
dist_check_SCRIPTS += pktio_run_dpdk.sh
endif

test_SCRIPTS = $(dist_check_SCRIPTS)
