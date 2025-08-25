#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015-2018 Linaro Limited
# Copyright (c) 2024 Nokia
#

# TEST_DIR is set by Makefile, when we add a rule to Makefile for odp_l2fwd_run
# we can use TEST_DIR the same way odp_pktio_run uses it now.
# If TEST_DIR is not set it means we are not running with make, and in this case
# there are two situations:
# 1. user build ODP in the same dir as the source (most likely)
#    here the user can simply call odp_l2fwd_run
# 2. user may have built ODP in a separate build dir (like bitbake usually does)
#    here the user has to do something like $ODP/test/performance/odp_l2fwd_run
#
# In both situations the script assumes that the user is in the directory where
# odp_l2fwd exists. If that's not true, then the user has to specify the path
# to it and run:
# TEST_DIR=$builddir $ODP/test/performance/odp_l2fwd_run

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
	echo "pktio_env has to be in current directory or in platform/\$ODP_PLATFORM/test."
	echo "ODP_PLATFORM=\"$ODP_PLATFORM\""
	exit 1
fi

run_l2fwd()
{
	setup_pktio_env clean # install trap to call cleanup_pktio_env

	if [ $? -ne 0 ]; then
		echo "setup_pktio_env error $?"
		exit $TEST_SKIPPED
	fi

	type odp_packet_gen > /dev/null
	if [ $? -ne 0 ]; then
		echo "odp_packet_gen not installed. Aborting."
		cleanup_pktio_env
		exit 1
	fi

	# Run odp_packet_gen with one tx thread
	GEN_LOG=odp_packet_gen_tmp.log
	(odp_packet_gen${EXEEXT} --gap 0 -i $IF0 \
			--ipv4_src 192.168.0.1 --ipv4_dst 192.168.0.2 \
			-r 0 -t 1 2>&1 > $GEN_LOG) \
			2>&1 > $GEN_LOG &

	GEN_PID=$!

	LOG=odp_l2fwd_tmp.log

	# Max 2 workers
	odp_l2fwd${EXEEXT} -i $IF1,$IF2 -m 0 -t 1 -c 2 --wait_link 10 | tee $LOG
	ret=${PIPESTATUS[0]}

	kill -2 ${GEN_PID}
	wait ${GEN_PID}

	if [ ! -f $LOG ]; then
		echo "FAIL: $LOG not found"
		ret=1
	elif [ $ret -eq 0 ]; then
		PASS_PPS=5000
		if [ "${TEST}" = "coverage" ]; then
			PASS_PPS=10
		fi
		MAX_PPS=$(awk '/TEST RESULT/ {print $3}' $LOG)
		NUMREG='^[0-9]+$'
		echo "PARSED PPS: $MAX_PPS"
		if ! [[ $MAX_PPS =~ $NUMREG ]]; then
			echo "FAIL: cannot parse $LOG"
			ret=1
		elif [ "$MAX_PPS" -lt "$PASS_PPS" ]; then
			echo -e "\nodp_packet_gen"
			echo "=============="
			cat $GEN_LOG
			echo -e "\nFAIL: pps below threshold $MAX_PPS < $PASS_PPS"
			ret=1
		fi
	fi

	rm -f $GEN_LOG
	rm -f $LOG

	cleanup_pktio_env

	exit $ret
}

case "$1" in
	setup)   setup_pktio_env   ;;
	cleanup) cleanup_pktio_env ;;
	*)       run_l2fwd ;;
esac
