#!/bin/bash
set -e

export TARGET_ARCH=i686-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CFLAGS="-m32"
	export CXXFLAGS="-m32"
	export LDFLAGS="-m32"
fi
export CPPFLAGS="-I/usr/include/i386-linux-gnu/dpdk"

exec "$(dirname "$0")"/build.sh
