#!/bin/bash
#
# (c) 2018, Linaro Limited
#
# SPDX-License-Identifier:     BSD-3-Clause

echo "Running server"

../fdserver &
# Give time to start the server
sleep 1

echo "Running reader"
./share_pipe_reader

killall -HUP fdserver
wait
