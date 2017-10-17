include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

dist_check_SCRIPTS = \
		     mmap_vlan_ins.sh \
		     pktio_env

dist_check_DATA = vlan.pcap

test_SCRIPTS = $(dist_check_SCRIPTS)
test_DATA = $(dist_check_DATA)

test_PROGRAMS = plat_mmap_vlan_ins

# Clonned from example odp_l2fwd simple
plat_mmap_vlan_ins_SOURCES = mmap_vlan_ins.c
