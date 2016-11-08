include $(top_srcdir)/test/Makefile.inc
TESTS_ENVIRONMENT += TEST_DIR=${top_builddir}/test/validation

dist_check_SCRIPTS = vlan.pcap \
		     mmap_vlan_ins.sh \
		     pktio_env

test_SCRIPTS = $(dist_check_SCRIPTS)

bin_PROGRAMS = plat_mmap_vlan_ins$(EXEEXT)
plat_mmap_vlan_ins_LDFLAGS = $(AM_LDFLAGS) -static
plat_mmap_vlan_ins_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/example

# Clonned from example odp_l2fwd simple
dist_plat_mmap_vlan_ins_SOURCES = mmap_vlan_ins.c
