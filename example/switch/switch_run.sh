#!/bin/bash
#
# Copyright (c) 2016-2018, Linaro Limited
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

RETVAL=0

setup_interfaces

./odp_switch${EXEEXT} -i $IF0,$IF1,$IF2,$IF3 -t 1
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  RETVAL=1
fi

validate_result

cleanup_interfaces

exit $RETVAL
