#!/bin/bash
set -e

# CC LD AR CXX has to be predifubed
#

export PKG_CONFIG_PATH="$HOME/cunit-install/x86_64/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}
export CROSS_ARCH=""

if [ "${CC#clang}" != "${CC}" ] ; then
	DPDKCC=clang ;
else
	DPDKCC=gcc ;
fi

export TARGET="x86_64$DPDKCC"

DPDK_SHARED="y"
$CWD/build_dpdk.sh

git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure \
	CFLAGS="-O0 -coverage" CXXFLAGS="-O0 -coverage" LDFLAGS="--coverage" \
	--enable-debug=full --enable-helper-linux
make clean
export CCACHE_DISABLE=1
make -j $(nproc)

ODP_SCHEDULER=basic    make check
ODP_SCHEDULER=sp       make check
ODP_SCHEDULER=iquery   make check
ODP_SCHEDULER=scalable make check
bash <(curl -s https://codecov.io/bash) -X coveragepy

cd ~
rm -rf ${TDIR}
