#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

cd "$(dirname "$0")"

if  [ -f ./pktio_env ]; then
  . ./pktio_env
else
  echo "ERROR: file not found: $(pwd)/pktio"
  exit 1
fi

# Exit code expected by automake for skipped tests
TEST_SKIPPED=77

if [ $(nproc --all) -lt 3 ]; then
  echo "Not enough CPU cores. Skipping test."
  exit $TEST_SKIPPED
fi

setup_interfaces

./odp_simple_pipeline${EXEEXT} -i $IF0,$IF1 -e -t 2
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

validate_result

cleanup_interfaces

exit 0
