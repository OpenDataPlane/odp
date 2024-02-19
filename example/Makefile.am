SUBDIRS = classifier \
	  debug \
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
	  timer \
	  traffic_mgmt

if HAVE_DW_ATOMIC_CMP_EXC
SUBDIRS += ipfragreass
endif

if helper_cli
SUBDIRS += cli
endif
