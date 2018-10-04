#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	--enable-user-guides

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

make distcheck

make clean

make distcheck DISTCHECK__CONFIGURE_FLAGS=--disable-abi-compat
