#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2024 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

run()
{
	# Maximum number of workers may be less than the number of available processors. One worker
	# should be always available.
	MAX_WORKERS=$(($(nproc) - 2))
	if [ $MAX_WORKERS -lt 1 ]; then
		MAX_WORKERS=1
	fi

	if [ $MAX_WORKERS -lt $1 ]; then
		echo "Not enough CPU cores (requested $1, available $MAX_WORKERS). Skipping test."
	else
		echo odp_sched_perf -p 0 -c $1
		echo ===============================================
		$TEST_DIR/odp_sched_perf${EXEEXT} -p 0 -c $1
		RET_VAL=$?
		if [ $RET_VAL -ne 0 ]; then
			echo odp_sched_perf FAILED
			exit $RET_VAL
		fi

		echo odp_sched_perf -p 1 -c $1
		echo ===============================================
		$TEST_DIR/odp_sched_perf${EXEEXT} -p 1 -c $1
		RET_VAL=$?
		if [ $RET_VAL -ne 0 ]; then
			echo odp_sched_perf FAILED
			exit $RET_VAL
		fi
	fi
}

run 1
run 2
run 6

exit 0
