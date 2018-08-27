#!/bin/bash
set -e

export TARGET_ARCH=arm-linux-gnueabihf
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi
export CPPFLAGS="-I/usr/include/${TARGET_ARCH}/dpdk"
export CFLAGS="-march=armv7-a"
export CXXFLAGS="-march=armv7-a"

exec "$(dirname "$0")"/build.sh
