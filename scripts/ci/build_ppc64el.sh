#!/bin/bash
set -e

export TARGET_ARCH=powerpc64le-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
	# DPDK clang build broken
	export CONF="${CONF} --disable-dpdk"

	# Ignore warnings about large atomic operation performance penalty
	export ODP_CFLAGS_EXTRA=-Wno-error=atomic-alignment

else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi
export CPPFLAGS="-I/usr/include/${TARGET_ARCH}/dpdk"

# Use target libraries
export PKG_CONFIG_PATH=
export PKG_CONFIG_LIBDIR=/usr/lib/${TARGET_ARCH}/pkgconfig

exec "$(dirname "$0")"/build.sh
