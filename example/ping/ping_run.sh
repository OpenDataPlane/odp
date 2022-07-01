#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
        echo "BUG: unable to find pktio_env!"
        echo "pktio_env has to be in current directory"
        exit 1
fi

setup_interfaces

# Ping test with 100 ICMP echo request packets. Timeout 5 sec.
# Promiscuous and verbose mode enabled.
./odp_ping${EXEEXT} -v -p -t 5 -n 100 -i $IF0
STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

echo "Pass: status ${STATUS}"

exit 0
