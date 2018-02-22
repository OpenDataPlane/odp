#!/bin/bash
#
# Copyright (c) 2018-2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

# directory where platform test sources are, including scripts
TEST_SRC_DIR=$(dirname $0)

# exit codes expected by automake for skipped tests
TEST_SKIPPED=77

# directories where binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH="${EXAMPLE_DIR}/:$PATH"
PATH="`pwd`/example/generator/:$PATH"
PATH="$(dirname $0)/../../../../../example/generator:$PATH"
PATH=".:$PATH"

bin_path=$(which odp_generator${EXEEXT})
if [ -x "$bin_path" ] ; then
	echo "running with odp_generator: $bin_path"
else
	echo "cannot odp_generator: please set you PATH for it."
	pwd
	echo $PATH
	exit 1
fi


odp_generator${EXEEXT} -w 1 -n 1 -I null:0 -m u
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

exit 0
