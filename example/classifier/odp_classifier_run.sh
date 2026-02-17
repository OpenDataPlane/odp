#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Marvell
#

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory"
	exit 1
fi

setup_interfaces

./odp_classifier${EXEEXT} -t $TIME_OUT_VAL -i $IF0 -m 0 -p \
	"ODP_PMR_SIP_ADDR:10.10.10.0:0xFFFFFF00:queue1" -P -C "queue1:${CPASS_COUNT_ARG1}" \
	-C "DefaultCos:${CPASS_COUNT_ARG2}"

STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

exit 0
