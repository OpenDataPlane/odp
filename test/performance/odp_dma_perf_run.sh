#!/bin/sh
#
# Copyright (c) 2022-2023, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
BIN_NAME=odp_dma_perf
SEGC=0
SEGS=1024
INFL=1
TIME=1
TESTS_RUN=0

check_result()
{
	if [ $1 -eq 0 ]; then
		TESTS_RUN=`expr $TESTS_RUN + 1`
	elif [ $1 -eq 1 ]; then
		echo "Test FAILED, exiting"
		exit 1
	else
		echo "Test SKIPPED"
	fi
}

echo "odp_dma_perf: synchronous DMA transfer 1"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -i $SEGC -o $SEGC -s $SEGS -S 0 -f $INFL -T $TIME -v

check_result $?

echo "odp_dma_perf: synchronous DMA transfer 2"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -i $SEGC -o $SEGC -s $SEGS -S 1 -f $INFL -T $TIME -v

check_result $?

echo "odp_dma_perf: asynchronous DMA transfer 1"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -i $SEGC -o $SEGC -s $SEGS -S 2 -m 0 -f $INFL -T $TIME -v

check_result $?

echo "odp_dma_perf: asynchronous DMA transfer 2"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -i $SEGC -o $SEGC -s $SEGS -S 3 -m 1 -f $INFL -T $TIME -v

check_result $?

echo "odp_dma_perf: SW transfer 1"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 2 -i $SEGC -o $SEGC -s $SEGS -S 0 -f $INFL -T $TIME -v

check_result $?

echo "odp_dma_perf: SW transfer 2"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 2 -i $SEGC -o $SEGC -s $SEGS -S 2 -f $INFL -T $TIME -v

check_result $?

if [ $TESTS_RUN -eq 0 ]; then
	exit 77
fi

exit 0
