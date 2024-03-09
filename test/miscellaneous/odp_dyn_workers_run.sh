#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia
#

MAX_CPUS=$(nproc)
# Frontend and control threads on one core and to-be-swapped worker thread on another core,
# otherwise weird issues might occur
REQ_CPUS=2
TEST_DIR="${TEST_DIR:-$(dirname $0)}"
BIN=odp_dyn_workers
DELAY=100000000

if [ ${MAX_CPUS} -lt ${REQ_CPUS} ]; then
	echo "Not enough CPUs (requested ${REQ_CPUS}, available ${MAX_CPUS}). Skipping test."
	exit 77
fi

taskset -c 0 ${TEST_DIR}/${BIN}${EXEEXT} -c 0x2,0x2 -p a0,d${DELAY},r0,d${DELAY},a1,d${DELAY},r1
