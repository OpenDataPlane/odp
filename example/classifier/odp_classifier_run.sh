#!/bin/bash
#
# Copyright (c) 2020, Marvell
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

SRC_DIR=$(dirname $0)
TEST_EXAMPLE_DIR=platform/$ODP_PLATFORM/test/example
PLATFORM_TEST_EXAMPLE=${SRC_DIR}/../../${TEST_EXAMPLE_DIR}

if  [ -f ./pktio_env ]; then
	. ./pktio_env
elif [ -f ${PLATFORM_TEST_EXAMPLE}/classifier/pktio_env ]; then
        . ${PLATFORM_TEST_EXAMPLE}/classifier/pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current or platform example directory"
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
