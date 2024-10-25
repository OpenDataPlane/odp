#!/bin/sh -xe
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia

TEST_DIR="${TEST_DIR:-$(dirname $0)}"

cd $TEST_DIR
BIN_DIR=../../../../test/performance
MODEL_DIR=../../example/ml

run_conv() {
        $BIN_DIR/odp_ml_perf${EXEEXT} -M $MODEL_DIR/conv.onnx \
                -I $MODEL_DIR/conv-input.bin -R $MODEL_DIR/conv-output.bin $@
}

run_conv -m 0 -r 1000
run_conv -m 0 -r 1000 -l
run_conv -m 2 -l
run_conv -m 3 -l
