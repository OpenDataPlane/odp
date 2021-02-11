SUBDIRS = classifier \
	  debug \
	  generator \
	  hello \
	  ipsec_api \
	  ipsec_crypto \
	  l2fwd_simple \
	  l3fwd \
	  packet \
	  ping \
	  simple_pipeline \
	  switch \
	  sysinfo \
	  time \
	  timer \
	  traffic_mgmt

if HAVE_DW_ATOMIC_CMP_EXC
SUBDIRS += ipfragreass
endif

if test_example
TESTS = \
	debug/odp_debug \
	generator/generator_run.sh \
	hello/odp_hello \
	sysinfo/odp_sysinfo \
	time/odp_time_global \
	timer/odp_timer_accuracy \
	timer/odp_timer_simple \
	traffic_mgmt/odp_traffic_mgmt

if HAVE_DW_ATOMIC_CMP_EXC
TESTS += ipfragreass/odp_ipfragreass
endif

if ODP_PKTIO_PCAP
TESTS += \
	classifier/odp_classifier_run.sh \
	l2fwd_simple/l2fwd_simple_run.sh \
	l3fwd/odp_l3fwd_run.sh \
	packet/packet_dump_run.sh \
	packet/pktio_run.sh \
	ping/ping_run.sh \
	simple_pipeline/simple_pipeline_run.sh \
	switch/switch_run.sh
endif

endif
