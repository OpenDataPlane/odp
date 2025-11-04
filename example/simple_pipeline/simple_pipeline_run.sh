#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019 Nokia
#

# Exit code expected by automake for skipped tests
TEST_SKIPPED=77

if  [ -f ./pktio_env ]; then
  . ./pktio_env
else
  echo "BUG: unable to find pktio_env!"
  echo "pktio_env has to be in current directory"
  exit 1
fi

if [ $(nproc --all) -lt 3 ]; then
  echo "Not enough CPU cores. Skipping test."
  exit $TEST_SKIPPED
fi

setup_interfaces

./odp_simple_pipeline${EXEEXT} -i $IF0,$IF1 -e -t 1 -a 1
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

validate_result

cleanup_interfaces

exit 0
