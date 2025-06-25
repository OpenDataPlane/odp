#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Nokia
#

# directory where test binaries have been built
TEST_DIR="${TEST_DIR:-$PWD}"

# directory where test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

PATH=$TEST_DIR:$PATH

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

VALIDATION_TESTDIR=platform/$ODP_PLATFORM/test/validation
PLATFORM_VALIDATION=${TEST_SRC_DIR}/../../$VALIDATION_TESTDIR

# Use installed pktio env or for make check take it from platform directory
if [ -f "./pktio_env" ]; then
	. ./pktio_env
elif  [ "$ODP_PLATFORM" = "" ]; then
	echo "$0: error: ODP_PLATFORM must be defined"
	# not skipped as this should never happen via "make check"
	exit 1
elif [ -f ${PLATFORM_VALIDATION}/api/pktio/pktio_env ]; then
	. ${PLATFORM_VALIDATION}/api/pktio/pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory or "
	echo "in platform/\$ODP_PLATFORM/test."
	echo "ODP_PLATFORM=\"$ODP_PLATFORM\""
	exit 1
fi

run_packet_gen()
{
	setup_pktio_env clean # install trap to call cleanup_pktio_env

	if [ $? -ne 0 ]; then
		echo "setup_pktio_env error $?"
		exit $TEST_SKIPPED
	fi

	# Runs 100 * 5 ms = 0.5 sec
	# Sends 100 packets through both interfaces => total 200 packets

	# Static packet length
	odp_packet_gen${EXEEXT} -i $IF0,$IF1 -b 1 -g 5000000 -q 100 -w 10
	ret=$?

	if [ $ret -eq 2 ]; then
		echo "FAIL: too few packets received"
	fi
	if [ $ret -ne 0 ]; then
		echo "FAIL: test failed: $ret"
		cleanup_pktio_env
		exit $ret
	fi

	# Random packet length
	odp_packet_gen${EXEEXT} -i $IF0,$IF1 -b 1 -g 5000000 -q 100 -L 60,1514,10 -w 10
	ret=$?

	if [ $ret -eq 2 ]; then
		echo "FAIL: too few packets received"
	fi
	if [ $ret -ne 0 ]; then
		echo "FAIL: test failed: $ret"
	fi

	cleanup_pktio_env

	exit $ret
}

case "$1" in
	setup)   setup_pktio_env   ;;
	cleanup) cleanup_pktio_env ;;
	*)       run_packet_gen ;;
esac
