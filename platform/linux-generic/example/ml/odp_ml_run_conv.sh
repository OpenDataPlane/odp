#!/bin/sh -xe
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia

../../../../example/ml/odp_ml_run${EXEEXT} -m conv.onnx -i conv-input.bin -r conv-output.bin
