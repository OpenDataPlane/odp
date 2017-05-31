#!/bin/sh
#
# Copyright (c) 2017, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# directories where time_main binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone (./time) intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/api/time:$PATH
PATH=$(dirname $0)/../../../../common_plat/validation/api/time:$PATH
PATH=$(dirname $0):$PATH
PATH=`pwd`:$PATH

time_main_path=$(which time_main${EXEEXT})
if [ -x "$time_main_path" ] ; then
	echo "running with time_main: $time_run_path"
else
	echo "cannot find time_main: please set you PATH for it."
	exit 1
fi

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

time_main${EXEEXT}
ret=$?

SIGSEGV=139

if [ "${TRAVIS}" = "true" ] && [ $ret -ne 0 ] &&
   [ ${TEST} = "coverage" ] && [ $ret -ne ${SIGSEGV} ]; then
	echo "SKIP: skip due significant slowdown under code coverage"
	exit ${TEST_SKIPPED}
fi

exit $ret
