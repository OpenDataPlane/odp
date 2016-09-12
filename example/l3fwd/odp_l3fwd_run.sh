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
echo "using PCAP_IN = ${PCAP_IN}, PCAP_OUT = ${PCAP_OUT}"

./odp_l3fwd -i pcap:in=${PCAP_IN},pcap:out=${PCAP_OUT} \
	    -r "10.0.0.0/24,pcap:out=${PCAP_OUT}" -d 30

STATUS=$?
PCAP_OUT_SIZE=`stat -c %s ${PCAP_OUT}`
rm -f ${PCAP_OUT}

if [ ${STATUS} -ne 0 ] || [ ${PCAP_IN_SIZE} -ne ${PCAP_OUT_SIZE} ]; then
	echo "Error: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"
	exit 1
fi

echo "Pass: status ${STATUS}, in:${PCAP_IN_SIZE} out:${PCAP_OUT_SIZE}"

exit 0
