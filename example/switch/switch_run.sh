#!/usr/bin/env bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2016-2018 Linaro Limited
#

RETVAL=0

if  [ -f ./pktio_env ]; then
  . ./pktio_env
else
  echo "BUG: unable to find pktio_env!"
  echo "pktio_env has to be in current directory"
  exit 1
fi

setup_interfaces

./odp_switch${EXEEXT} -i $IF0,$IF1,$IF2,$IF3 -t 1 -a 1
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  RETVAL=1
fi

validate_result

cleanup_interfaces

exit $RETVAL
