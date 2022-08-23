#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

SRC_DIR=$(dirname $0)
TEST_EXAMPLE_DIR=platform/$ODP_PLATFORM/test/example
PLATFORM_TEST_EXAMPLE=${SRC_DIR}/../../${TEST_EXAMPLE_DIR}

if  [ -f ./pktio_env ]; then
	. ./pktio_env
elif [ -f ${PLATFORM_TEST_EXAMPLE}/ping/pktio_env ]; then
        . ${PLATFORM_TEST_EXAMPLE}/ping/pktio_env
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

# Ping test with 100 ICMP echo request packets. Timeout 5 sec.
# Promiscuous and verbose mode enabled.
$STDBUF ./odp_ping${EXEEXT} -v -p -t 5 -n 100 -i $IF0
STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

echo "Pass: status ${STATUS}"

exit 0
