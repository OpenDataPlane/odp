#!/bin/bash
set -e

CONFIG_OPT="--prefix=/opt/odp ${CONF}"

cd "$(dirname "$0")"/../..
./bootstrap
echo "./configure $CONFIG_OPT"
./configure $CONFIG_OPT

make clean

make -j $(nproc)

make install

make installcheck
