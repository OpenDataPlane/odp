#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

# Use short run time in make check

$TEST_DIR/odp_cpu_bench${EXEEXT} -t 1

if [ $? -ne 0 ] ; then
    echo Test FAILED
    exit 1
fi

exit 0
