#!/bin/bash
set -e

export TARGET_ARCH=powerpc-linux-gnu
if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=${TARGET_ARCH}"
	export CXX="clang++ --target=${TARGET_ARCH}"
else
	export CC="${TARGET_ARCH}-gcc"
	export CXX="${TARGET_ARCH}-g++"
fi
# No DPDK on PowerPC
export CONF="${CONF} --disable-dpdk"

exec "$(dirname "$0")"/build.sh
