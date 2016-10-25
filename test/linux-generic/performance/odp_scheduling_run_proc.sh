#!/bin/sh
#
# Copyright (c) 2016, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#
# Script that passes command line arguments to odp_scheduling test when
# launched by 'make check'

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
PERFORMANCE="$TEST_DIR/../../common_plat/performance"
ret=0
ALL=0

run()
{
	echo odp_scheduling_run starts requesting $1 worker threads
	echo =====================================================

	$PERFORMANCE/odp_scheduling${EXEEXT} --odph_proc -c $1 || ret=1
}

run 1
run 5
run 8
run 11
run $ALL

exit $ret
