#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#
TEST_SRC_DIR=$(dirname $0)
TEST_DIR="${TEST_DIR:-$(dirname $0)}"

DURATION=5
LOG=odp_pktio_ordered.log
LOOPS=100000000
PASS_PPS=5000
PCAP_IN=`find . ${TEST_SRC_DIR} $(dirname $0) -name udp64.pcap -print -quit`
PCAP_OUT=/dev/null

if [ ! -f ${PCAP_IN} ]; then
	echo "FAIL: no udp64.pcap"
	exit 1
fi

# This just turns off output buffering so that you still get periodic
# output while piping to tee, as long as stdbuf is available.
if [ "$(which stdbuf)" != "" ]; then
	STDBUF="stdbuf -o 0"
else
	STDBUF=
fi

$STDBUF ${TEST_DIR}/odp_pktio_ordered${EXEEXT} \
	-i pcap:in=${PCAP_IN}:loops=$LOOPS,pcap:out=${PCAP_OUT} \
	-t $DURATION | tee $LOG
ret=${PIPESTATUS[0]}

if [ $ret -ne 0 ]; then
	echo "FAIL: no odp_pktio_ordered${EXEEXT}"
	rm -f $LOG
	exit $ret
fi

if [ ! -f $LOG ]; then
	echo "FAIL: $LOG not found"
	ret=1
	exit $ret
fi

MAX_PPS=$(awk '/TEST RESULT/ {print $3}' $LOG)
echo "MAX_PPS=$MAX_PPS"
if [ $MAX_PPS -lt $PASS_PPS ]; then
	echo "FAIL: pps below threshold $MAX_PPS < $PASS_PPS"
	ret=1
fi

rm -f $LOG

exit $ret
