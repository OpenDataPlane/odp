#!/bin/sh
TEST_DIR="${TEST_DIR:-$(dirname $0)/..}/ipsec"
$TEST_DIR/ipsec_main$EXEEXT async
