#!/bin/sh
#
# Copyright (c) 2015-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#
# Script that passes command line arguments to odp_scheduling test when
# launched by 'make check'

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
ALL=0

run()
{
	echo odp_scheduling_run starts requesting $1 worker threads
	echo ======================================================

	if [ $(nproc) -lt $1 ]; then
		echo "Not enough CPU cores. Skipping test."
	else
		$TEST_DIR/odp_scheduling${EXEEXT} -c $1 -t 0.1
		RET_VAL=$?
		if [ $RET_VAL -ne 0 ]; then
			echo odp_scheduling FAILED
			exit $RET_VAL
		fi
	fi
}

run 1
run 5
run 8
run 11
run $ALL

exit 0
