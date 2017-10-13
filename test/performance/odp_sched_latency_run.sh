#!/bin/sh
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#
# Script that passes command line arguments to odp_sched_latency test when
# launched by 'make check'

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
ALL=0

run()
{
	echo odp_sched_latency_run starts requesting $1 worker threads
	echo ===============================================

	$TEST_DIR/odp_sched_latency${EXEEXT} -c $1 || exit $?
}

run 1
run 5
run 8
run 11
run $ALL

exit 0
