#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#

TEST_DIR="${TEST_DIR:-$PWD}"
TEST_SRC_DIR=$(dirname $0)
PERF_TEST_DIR=platform/${ODP_PLATFORM}/test/performance
PERF_TEST_DIR=${TEST_SRC_DIR}/../../${PERF_TEST_DIR}

BIN_NAME=odp_dmafwd
BATCH=10
TIME=0.1
TESTS_RUN=0

check_env()
{
	if [ -f "./pktio_env" ]; then
		. ./pktio_env
	elif  [ "${ODP_PLATFORM}" = "" ]; then
		echo "$0: ERROR: ODP_PLATFORM must be defined"
		exit 1
	elif [ -f ${PERF_TEST_DIR}/dmafwd/pktio_env ]; then
		. ${PERF_TEST_DIR}/dmafwd/pktio_env
	else
		echo "ERROR: unable to find pktio_env"
		echo "pktio_env has to be in current directory or in platform/\$ODP_PLATFORM/test/"
		echo "ODP_PLATFORM=\"${ODP_PLATFORM}\""
		exit 1
	fi
}

check_result()
{
	if [ $1 -eq 0 ]; then
		TESTS_RUN=`expr $TESTS_RUN + 1`
	elif [ $1 -eq 1 ]; then
		echo "Test FAILED, exiting"
		exit 1
	else
		echo "Test SKIPPED"
		return 0
	fi

	validate_result
}

check_exit()
{
	if [ $TESTS_RUN -eq 0 ]; then
		exit 77
	fi

	exit 0
}

check_env
setup_interfaces
echo "${BIN_NAME}: SW copy"
echo "==================="
./${BIN_NAME}${EXEEXT} -i ${IF0} -b ${BATCH} -T ${TIME} -t 0
check_result $?
echo "${BIN_NAME}: DMA copy event"
echo "===================="
./${BIN_NAME}${EXEEXT} -i ${IF0} -b ${BATCH} -T ${TIME} -t 1
check_result $?
echo "${BIN_NAME}: DMA copy poll"
echo "===================="
./${BIN_NAME}${EXEEXT} -i ${IF0} -b ${BATCH} -T ${TIME} -t 2
check_result $?
cleanup_interfaces
check_exit
