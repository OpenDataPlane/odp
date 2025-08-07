#!/usr/bin/env bash
set -e

export TARGET_ARCH=arm-linux-gnueabihf
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi
export CFLAGS="-march=armv7-a"
export CXXFLAGS="-march=armv7-a"

# No DPDK on ARMv7
export CONF="${CONF} --disable-dpdk"

# Use target libraries
export PKG_CONFIG_PATH=
export PKG_CONFIG_LIBDIR=/usr/lib/${TARGET_ARCH}/pkgconfig

exec "$(dirname "$0")"/build.sh
