#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name icmp_echo_req.pcap -print -quit`
PCAP_OUT="pcapout.pcap"
PCAP_IN_SIZE=`stat -c %s ${PCAP_IN}`
echo "using PCAP in=${PCAP_IN}:out=${PCAP_OUT} size %${PCAP_IN_SIZE}"

# Ping test with 100 ICMP echo request packets (verbose mode)
./odp_ping${EXEEXT} -v -n 100 -ipcap:in=${PCAP_IN}:out=${PCAP_OUT}
STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 1
fi
echo "Pass: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

exit 0
