SUBDIRS = classifier \
	  debug \
	  hello \
	  ipsec_api \
	  ipsec_crypto \
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

if WITH_ML
SUBDIRS += ml
endif
