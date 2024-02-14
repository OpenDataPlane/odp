#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2024 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

$TEST_DIR/odp_timer_accuracy${EXEEXT} -p 100000000 -n 10

RET_VAL=$?
if [ $RET_VAL -ne 0 ] ; then
    echo odp_timer_accuracy FAILED
    exit $RET_VAL
fi

exit 0
