#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#

set -e

# cd to the directory where this script is in
cd "$( dirname "${BASH_SOURCE[0]}" )"

python3 simple_linear_gen.py

python3 batch_add_gen.py
