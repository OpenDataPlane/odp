#!/usr/bin/env bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

# Required by CentOS and Rocky Linux to find DPDK install
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/local/lib64/pkgconfig:/usr/lib/pkgconfig/

exec "$(dirname "$0")"/build.sh
