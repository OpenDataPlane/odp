#!/bin/bash
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

PCAP_IN=`find . ../../pcap -name udp64.pcap -print -quit`
echo "using PCAP_IN = ${PCAP_IN}"

./odp_l2fwd_simple pcap:in=${PCAP_IN} pcap:out=pcapout.pcap 02:00:00:00:00:01 02:00:00:00:00:02 &

sleep 1
kill $!
wait $!
STATUS=$?

if [ "$STATUS" -ne 143 ]; then
  echo "Error: status was: $STATUS, expected 143"
  exit 1
fi

if [ `stat -c %s pcapout.pcap` -ne `stat -c %s  ${PCAP_IN}` ]; then
  echo "File sizes disagree"
  exit 1
fi

rm -f pcapout.pcap

exit 0
