#!/bin/sh
#
# Copyright (c) 2021, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

echo odp_sched_perf: buffer pool
echo ===============================================

$TEST_DIR/odp_sched_perf${EXEEXT} -p 0

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_sched_perf -p 0: FAILED
	exit $RET_VAL
fi

echo odp_sched_perf: packet pool
echo ===============================================

$TEST_DIR/odp_sched_perf${EXEEXT} -p 1

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_sched_perf -p 1: FAILED
	exit $RET_VAL
fi

exit 0
