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

echo odp_timer_perf: timer start and cancel mode
echo ===============================================

$TEST_DIR/odp_timer_perf${EXEEXT} -m 1 -c 1 -t 10 -R 50

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_timer_perf -m 1: FAILED
	exit $RET_VAL
fi

echo odp_timer_perf: timer start and expire mode
echo ===============================================

$TEST_DIR/odp_timer_perf${EXEEXT} -m 2 -c 1 -R 10

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_timer_perf -m 2: FAILED
	exit $RET_VAL
fi

echo odp_timer_perf: timer pool control mode
echo ===============================================

$TEST_DIR/odp_timer_perf${EXEEXT} -m 3 -c 1 -R 10

RET_VAL=$?
if [ $RET_VAL -ne 0 ]; then
	echo odp_timer_perf -m 3: FAILED
	exit $RET_VAL
fi

exit 0
