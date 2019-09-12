#!/bin/sh
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# any parameter passed as arguments to this script is passed unchanged to
# the test itself (pktio_main)

# directories where pktio_main binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone (./pktio_run) intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/api/pktio:$PATH
PATH=$(dirname $0):$PATH
PATH=$(dirname $0)/../../../../../../test/validation/api/pktio:$PATH
PATH=.:$PATH

pktio_main_path=$(which pktio_main${EXEEXT})
if [ -x "$pktio_main_path" ] ; then
	echo "running with pktio_main: $pktio_main_path"
else
	echo "cannot find pktio_main: please set you PATH for it."
fi

# directory where platform test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

# Use installed pktio env or for make check take it from the test directory
if [ -f "./pktio_env" ]; then
	. ./pktio_env
elif [ -f ${TEST_SRC_DIR}/pktio_env ]; then
	. ${TEST_SRC_DIR}/pktio_env
else
	echo "ERROR: unable to find pktio_env!"
	echo "pktio_env has to be in current directory or in ${TEST_SRC_DIR}"
	exit 1
fi

run_test()
{
	local ret=0

	pktio_main${EXEEXT} $*
	ret=$?

	if [ $ret -ne 0 ]; then
		echo "!!! FAILED !!!"
	fi

	return $ret
}

run_test_vale()
{
	# use two vale ports on the same switch
	export ODP_PKTIO_IF0=valetest:0
	export ODP_PKTIO_IF1=valetest:1
	run_test
	return $?
}

run_test_pipe()
{
	# use a netmap pipe
	export ODP_PKTIO_IF0=valetest:0{0
	export ODP_PKTIO_IF1=valetest:0}0
	run_test
	return $?
}

run_test_veth()
{
	if [ "$(lsmod | grep veth)" = "" ]; then
		echo "netmap enabled veth module not loaded, skipping test."
		return 0
	fi

	setup_pktio_env clean
	export ODP_PKTIO_IF0=netmap:$IF0
	export ODP_PKTIO_IF1=netmap:$IF1
	run_test
	return $?
}

run()
{
	local ret=0

	# need to be root to run these tests
	if [ "$(id -u)" != "0" ]; then
		echo "netmap tests must be run as root, skipping test."
		exit $TEST_SKIPPED
	fi

	if [ "$(lsmod | grep netmap)" = "" ]; then
		echo "netmap kernel module not loaded, skipping test."
		exit $TEST_SKIPPED
	fi

	if [ "$ODP_PKTIO_IF0" != "" ]; then
		run_test
		ret=$?
	else
		run_test_vale
		r=$?; [ $ret = 0 ] && ret=$r
		run_test_pipe
		r=$?; [ $ret = 0 ] && ret=$r
		run_test_veth
		r=$?; [ $ret = 0 ] && ret=$r
	fi

	exit $ret
}

run
