#!/usr/bin/env bash
set -e

export TARGET_ARCH=aarch64-linux-gnu
if [[ $(uname -m) =~ ^(arm64|aarch64)$ ]]; then
  export BUILD_ARCH=aarch64-linux-gnu
fi

if [ "$TARGET_ARCH" == "$BUILD_ARCH" ]; then
	# Native build
	if [ "${CC#clang}" != "${CC}" ] ; then
		export CXX="clang++"
	fi

	# Required by CentOS and Rocky Linux to find DPDK install
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig

else
	# Cross compilation
	if [ "${CC#clang}" != "${CC}" ] ; then
		export CC="clang --target=${TARGET_ARCH}"
		export CXX="clang++ --target=${TARGET_ARCH}"
	else
		export CC="${TARGET_ARCH}-gcc"
		export CXX="${TARGET_ARCH}-g++"
	fi

	export CPPFLAGS="-I/usr/include/${TARGET_ARCH}/dpdk"

	# Use target libraries
	export PKG_CONFIG_PATH=
	export PKG_CONFIG_LIBDIR=/usr/lib/${TARGET_ARCH}/pkgconfig:/usr/local/lib/${TARGET_ARCH}/pkgconfig
fi

# ARMv8 crypto
export PKG_CONFIG_PATH=~/aarch64cryptolib/pkgconfig:$PKG_CONFIG_PATH

exec "$(dirname "$0")"/build.sh
