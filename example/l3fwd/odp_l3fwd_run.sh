#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

cd "$(dirname "$0")"

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
	echo "ERROR: file not found: $(pwd)/pktio"
	exit 1
fi

setup_interfaces

./odp_l3fwd${EXEEXT} -i $IF0,$IF1 -r "10.0.0.0/24,$IF1" -d 30

STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

exit 0
