#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

SRC_DIR=$(dirname $0)
TEST_EXAMPLE_DIR=platform/$ODP_PLATFORM/test/example
PLATFORM_TEST_EXAMPLE=${SRC_DIR}/../../${TEST_EXAMPLE_DIR}

if  [ -f ./pktio_env ]; then
	. ./pktio_env
elif [ -f ${PLATFORM_TEST_EXAMPLE}/packet/pktio_env ]; then
        . ${PLATFORM_TEST_EXAMPLE}/packet/pktio_env
else
        echo "BUG: unable to find pktio_env!"
        echo "pktio_env has to be in current or platform example directory"
        exit 1
fi

setup_interfaces

if [ "$(which stdbuf)" != "" ]; then
	STDBUF="stdbuf -o 0"
else
	STDBUF=
fi

# burst mode
$STDBUF ./odp_pktio${EXEEXT} -i $IF1 -t 1 -m 0
STATUS=$?
if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result
echo "Pass -m 0: status ${STATUS}"

# queue mode
$STDBUF ./odp_pktio${EXEEXT} -i $IF1 -t 1 -m 1
STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 2
fi

validate_result
echo "Pass -m 1: status ${STATUS}"

# sched/queue mode
$STDBUF ./odp_pktio${EXEEXT} -i $IF1 -t 1 -m 2
STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 3
fi

validate_result
echo "Pass -m 2: status ${STATUS}"

# cpu number option test 1
$STDBUF ./odp_pktio${EXEEXT} -i $IF1 -t 1 -m 0 -c 1
STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 4
fi

validate_result
echo "Pass -m 0 -c 1: status ${STATUS}"

cleanup_interfaces

exit 0
