#!/bin/bash
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#
set -e

# wget https://github.com/onnx/models/raw/main/validated/vision/classification/mnist/model/mnist-12.onnx
./mnist${EXEEXT} mnist-12.onnx example_digit.csv
