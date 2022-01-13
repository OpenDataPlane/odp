#!/bin/sh
#
# Copyright (c) 2022, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause

TEST_DIR="${TEST_DIR:-$(dirname $0)}"
BIN_NAME=odp_dma_perf
SEG_SIZE=1024
ROUNDS=1000
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

echo "odp_dma_perf: synchronous transfer 1"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -g 0 -i 6 -s $SEG_SIZE -T 0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: synchronous transfer 2"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -g 1 -i 6 -s $SEG_SIZE -T 0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: synchronous transfer 3"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -g 0 -i 6 -s $SEG_SIZE -T 1 -r $ROUNDS

check_result $?

echo "odp_dma_perf: synchronous transfer 4"
echo "===================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 0 -g 1 -i 6 -s $SEG_SIZE -T 1 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 1"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 0 -i 6 -s $SEG_SIZE -T 0 -m 0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 2"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 1 -i 6 -s $SEG_SIZE -T 0 -m 0,0,0,0,0,0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 3"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 1 -i 6 -s $SEG_SIZE -T 0 -m 0,0,0,0,0,1 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 4"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 0 -i 6 -s $SEG_SIZE -T 1 -m 0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 5"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 1 -i 6 -s $SEG_SIZE -T 1 -m 0,0,0,0,0,0 -r $ROUNDS

check_result $?

echo "odp_dma_perf: asynchronous transfer 6"
echo "====================================="

${TEST_DIR}/${BIN_NAME}${EXEEXT} -t 1 -g 1 -i 6 -s $SEG_SIZE -T 1 -m 0,0,0,0,0,1 -r $ROUNDS

check_result $?

if [ $TESTS_RUN -eq 0 ]; then
	exit 77
fi

exit 0
