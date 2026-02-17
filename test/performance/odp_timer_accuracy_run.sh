#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2024 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

for mode in 0 1 2 3 4; do

    $TEST_DIR/odp_timer_accuracy${EXEEXT} -m $mode -p 100000000 -n 10

    RET_VAL=$?
    if [ $RET_VAL -ne 0 ] ; then
        echo "odp_timer_accuracy (mode $mode) FAILED"
        exit $RET_VAL
    fi

done

exit 0
