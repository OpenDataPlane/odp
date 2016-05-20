#!/bin/bash
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

NUM_RX_PORT=3
RETVAL=0

PCAP_IN=`find . ../../pcap -name udp64.pcap -print -quit`

echo "Switch test using PCAP_IN = ${PCAP_IN}"

RX_PORTS=""
for i in `seq 1 $NUM_RX_PORT`;
do
	RX_PORTS="${RX_PORTS},pcap:out=pcapout${i}.pcap"
done

./odp_switch -i pcap:in=${PCAP_IN}${RX_PORTS} &

sleep 1
kill $!
wait $!
STATUS=$?

if [ "$STATUS" -ne 143 ]; then
  echo "Error: status was: $STATUS, expected 143"
  RETVAL=1
fi

for i in `seq 1 $NUM_RX_PORT`;
do
	if [ `stat -c %s pcapout${i}.pcap` -ne `stat -c %s ${PCAP_IN}` ]; then
		echo "Error: Output file $i size not matching"
		RETVAL=1
	fi
	rm -f pcapout${i}.pcap
done

exit $RETVAL
