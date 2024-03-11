#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022 Nokia
#

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

# Run with a small number of packets in make check

$TEST_DIR/odp_ipsec${EXEEXT} -c 100

if [ $? -ne 0 ] ; then
    echo Test FAILED
    exit 1
fi

exit 0
