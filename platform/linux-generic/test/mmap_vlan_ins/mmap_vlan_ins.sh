#!/bin/sh
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

#
# This test is intend to test pkt_mmap_vlan_insert() feature for
# linux-generic packet mmap pktio.
#
#
export ODP_PKTIO_DISABLE_SOCKET_MMSG=1

# directory where platform test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

# directories where binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/../mmap_vlan_ins:$PATH
PATH=`pwd`/mmap_vlan_ins:$PATH
PATH=$(dirname $0):$PATH
PATH=.:$PATH

bin_path=$(which plat_mmap_vlan_ins${EXEEXT})
if [ -x "$bin_path" ] ; then
	echo "running with plat_mmap_vlan_ins: $bin_path"
else
	echo "cannot find plat_mmap_vlan_ins: please set you PATH for it."
	pwd
	exit 1
fi


# Use installed pktio env or for make check take it from platform directory
if [ -f "./pktio_env" ]; then
	. ./pktio_env
elif [ -f ${TEST_SRC_DIR}/pktio_env ]; then
	. ${TEST_SRC_DIR}/pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory or"
	echo " in platform/\$ODP_PLATFORM/test."
	echo "ODP_PLATFORM=\"$ODP_PLATFORM\""
	exit 1
fi

setup_pktio_env
if [ $? -ne 0 ]; then
	return 77 # Skip the test
fi

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name vlan.pcap -print -quit`
echo "using PCAP_IN = ${PCAP_IN}"
PCAP_OUT=vlan_out.pcap

# Listen on veth pipe and write to pcap Send pcap
plat_mmap_vlan_ins${EXEEXT} pktiop0p1 pcap:out=${PCAP_OUT} \
	00:02:03:04:05:06 00:08:09:0a:0b:0c &
# Send pcap file to veth interface
plat_mmap_vlan_ins${EXEEXT} pcap:in=${PCAP_IN} pktiop1p0 \
	01:02:03:04:05:06 01:08:09:0a:0b:0c

rm -f ${PCAP_OUT}
cleanup_pktio_env

exit 0
