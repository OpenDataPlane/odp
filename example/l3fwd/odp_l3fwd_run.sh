#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2016-2018 Linaro Limited
#

if  [ -f ./pktio_env ]; then
	. ./pktio_env
else
	echo "BUG: unable to find pktio_env!"
	echo "pktio_env has to be in current directory"
	exit 1
fi

setup_interfaces

./odp_l3fwd${EXEEXT} -i $IF0,$IF1 -r "10.0.0.0/24,$IF1" -d 1

STATUS=$?

if [ ${STATUS} -ne 0 ]; then
	echo "Error: status ${STATUS}"
	exit 1
fi

validate_result

cleanup_interfaces

exit 0
