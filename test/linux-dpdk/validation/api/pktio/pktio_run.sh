#!/bin/sh
#
# Copyright (c) 2015, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# Proceed the pktio tests. This script expects at least one argument:
#	setup)   setup the pktio test environment
#	cleanup) cleanup the pktio test environment
#	run)     run the pktio tests (setup, run, cleanup)
# extra arguments are passed unchanged to the test itself (pktio_main)
# Without arguments, "run" is assumed and no extra argument is passed to the
# test (legacy mode).
#

# directories where pktio_main binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone (./pktio_run) intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/api/pktio:$PATH
PATH=$(dirname $0):$PATH
PATH=$(dirname $0)/../../../../common_plat/validation/api/pktio:$PATH
PATH=.:$PATH

pktio_main_path=$(which pktio_main${EXEEXT})
if [ -x "$pktio_main_path" ] ; then
	echo "running with pktio_main: $pktio_run_path"
else
	echo "cannot find pktio_main: please set you PATH for it."
fi

# directory where platform test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

# Use installed pktio env or for make check take it from platform directory
if [ -f "./pktio_env" ]; then
	. ./pktio_env
elif [ -f ${TEST_SRC_DIR}/pktio_env ]; then
	. ${TEST_SRC_DIR}/pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory or in platform/\$ODP_PLATFORM/test."
	echo "ODP_PLATFORM=\"$ODP_PLATFORM\""
	exit 1
fi

run_test()
{
	local ret=0

	pktio_main${EXEEXT} $*
	if [ $? -ne 0 ]; then
		ret=1
	fi
	if [ $ret -ne 0 ]; then
		echo "!!! FAILED !!!"
	fi

	return $ret
}

run()
{
	echo "pktio: using 'loop' device"
	$ODP_GDB pktio_main${EXEEXT} $*
	loop_ret=$?

	# need to be root to run tests with real interfaces
	if [ "$(id -u)" != "0" ]; then
		exit $ret
	fi

	if [ "$ODP_PKTIO_IF0" = "" ]; then
		# no interfaces specified, use default veth interfaces
		# setup by the pktio_env script
		setup_pktio_env clean
		if [ $? != 0 ]; then
			echo "Failed to setup test environment, skipping test."
			exit $TEST_SKIPPED
		fi
		export ODP_PLATFORM_PARAMS="-n 4 --vdev eth_pcap0,iface=$IF0 --vdev eth_pcap1,iface=$IF1"
		export ODP_PKTIO_IF0=0
		export ODP_PKTIO_IF1=1
	fi

	run_test
	ret=$?

	[ $ret = 0 ] && ret=$loop_ret

	exit $ret
}

if [ $# != 0 ]; then
	action=$1
	shift
fi

case "$action" in
	setup)   setup_pktio_env   ;;
	cleanup) cleanup_pktio_env ;;
	run)     run ;;
	*)       run ;;
esac
