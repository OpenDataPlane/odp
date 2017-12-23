#!/bin/bash
#
# Copyright (c) 2018, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause
#

./odp_generator${EXEEXT} -w 1 -n 1 -I null:0 -m u
STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo "Error: status was: $STATUS, expected 0"
  exit 1
fi

exit 0
