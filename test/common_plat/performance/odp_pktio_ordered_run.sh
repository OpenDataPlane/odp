#!/bin/bash
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

DURATION=5
LOG=odp_pktio_ordered.log
LOOPS=100000000
PASS_PPS=5000
PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`
PCAP_OUT=/dev/null

# This just turns off output buffering so that you still get periodic
# output while piping to tee, as long as stdbuf is available.
if [ "$(which stdbuf)" != "" ]; then
	STDBUF="stdbuf -o 0"
else
	STDBUF=
fi

$STDBUF ./odp_pktio_ordered${EXEEXT} -i pcap:in=${PCAP_IN}:loops=$LOOPS,\
pcap:out=${PCAP_OUT} -t $DURATION | tee $LOG

ret=$?

if [ ! -f $LOG ]; then
	echo "FAIL: $LOG not found"
	ret=1
elif [ $ret -eq 0 ]; then
	MAX_PPS=$(awk '/TEST RESULT/ {print $3}' $LOG)
	if [ "$MAX_PPS" -lt "$PASS_PPS" ]; then
		echo "FAIL: pps below threshold $MAX_PPS < $PASS_PPS"
		ret=1
	fi
fi

rm -f $LOG

exit $ret
