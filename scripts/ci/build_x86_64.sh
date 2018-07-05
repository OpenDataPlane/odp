#!/bin/bash
set -e

export CC=gcc
export LD=ld
export AR=ar

#export PKG_CONFIG_PATH=/usr/lib/arm-linux-gnueabihf/pkgconfig:/usr/arm-linux-gnueabihf/pkgconfig
export PKG_CONFIG_PATH="$HOME/cunit-install/x86_64/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}

export CROSS_ARCH=""
#export DPDK_CROSS=arm-linux-gnueabihf-

if [ "${CC#clang}" != "${CC}" ] ; then
DPDKCC=clang ;
else
DPDKCC=gcc ;
fi

export TARGET="x86_64$DPDKCC"

$CWD/build_dpdk.sh

git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure --host=x86_64-linux-gnu --build=x86_64-linux-gnu
make clean
make -j 8
make check
cd ~
rm -rf ${TDIR}
