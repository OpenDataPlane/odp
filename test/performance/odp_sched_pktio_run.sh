#!/bin/sh
#
# Copyright (c) 2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# directory where test binaries have been built
TEST_DIR="${TEST_DIR:-$PWD}"
# directory where test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

PATH=$TEST_DIR:$TEST_DIR/../../example/generator:$PATH

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

VALIDATION_TESTDIR=platform/$ODP_PLATFORM/test/validation
PLATFORM_VALIDATION=${TEST_SRC_DIR}/../../$VALIDATION_TESTDIR

FLOOD_MODE=0

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

run_sched_pktio()
{
	setup_pktio_env clean # install trap to call cleanup_pktio_env

	if [ $? -ne 0 ]; then
		echo "setup_pktio_env error $?"
		exit $TEST_SKIPPED
	fi

	type odp_generator > /dev/null
	if [ $? -ne 0 ]; then
		echo "odp_generator not installed. Aborting."
		cleanup_pktio_env
		exit 1
	fi

	if [ "$(which stdbuf)" != "" ]; then
		STDBUF="stdbuf -o 0"
	else
		STDBUF=
	fi

	# 1 worker
	$STDBUF odp_sched_pktio${EXEEXT} -i $IF1,$IF2 -c 1 -s &

	TEST_PID=$!

	sleep 1

	# Run generator with one worker
	(odp_generator${EXEEXT} --interval $FLOOD_MODE -I $IF0 \
			--srcip 192.168.0.1 --dstip 192.168.0.2 \
			-m u -w 1 2>&1 > /dev/null) \
			2>&1 > /dev/null &

	GEN_PID=$!

	# Run test for 5 sec
	sleep 5

	kill -2 ${GEN_PID}
	wait ${GEN_PID}

	# Kill with SIGINT to output statistics
	kill -2 ${TEST_PID}
	wait ${TEST_PID}

	ret=$?

	if [ $ret -eq 3 ]; then
		echo "PASS: received and transmitted over 5000 packets"
		ret=0
	else
		echo "FAIL: less than thousand rx or tx packets $ret"
		ret=1
	fi

	cleanup_pktio_env

	exit $ret
}

case "$1" in
	setup)   setup_pktio_env   ;;
	cleanup) cleanup_pktio_env ;;
	*)       run_sched_pktio ;;
esac
