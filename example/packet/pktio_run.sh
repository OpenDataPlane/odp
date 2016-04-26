#!/bin/bash
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

PCAP_IN=`find . ${TEST_DIR} $(dirname $0) -name udp64.pcap -print -quit`
PCAP_OUT="pcapout.pcap"
PCAP_IN_SIZE=`stat -c %s ${PCAP_IN}`
echo "using PCAP in=${PCAP_IN}:out=${PCAP_OUT} size %${PCAP_IN_SIZE}"

# burst mode
./odp_pktio -ipcap:in=${PCAP_IN}:out=${PCAP_OUT} -t 5 -m 0
STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 1
fi
echo "Pass -m 0: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

# queue mode
./odp_pktio -ipcap:in=${PCAP_IN}:out=${PCAP_OUT} -t 5 -m 1
STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 2
fi
echo "Pass -m 1: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

# sched/queue mode
./odp_pktio -ipcap:in=${PCAP_IN}:out=${PCAP_OUT} -t 5 -m 2
STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 3
fi
echo "Pass -m 2: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

# cpu number option test 1
./odp_pktio -ipcap:in=${PCAP_IN}:out=${PCAP_OUT} -t 5 -m 0 -c 1
STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 4
fi
echo "Pass -m 0 -c 1: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

exit 0
