#!/bin/sh
#
# Copyright (c) 2017, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# directory where test binaries have been built
TEST_DIR="${TEST_DIR:-$(dirname $0)}"

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

${TEST_DIR}/traffic_mngr_main${EXEEXT}
ret=$?

SIGSEGV=139

if [ "${TRAVIS}" = "true" ] && [ $ret -ne 0 ] && [ $ret -ne ${SIGSEGV} ]; then
	echo "SKIP: skip due to not isolated environment"
	exit ${TEST_SKIPPED}
fi

exit $ret
