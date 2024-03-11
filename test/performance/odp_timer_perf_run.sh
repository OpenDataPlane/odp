#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

echo odp_timer_perf: odp_schedule overhead mode
echo ===============================================

$TEST_DIR/odp_timer_perf${EXEEXT} -m 0 -c 1

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_timer_perf -m 0: FAILED
	exit $RET_VAL
fi

echo odp_timer_perf: timer set + cancel mode
echo ===============================================

$TEST_DIR/odp_timer_perf${EXEEXT} -m 1 -c 1 -t 10 -R 50

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_timer_perf -m 1: FAILED
	exit $RET_VAL
fi

exit 0
