#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CC="clang --target=aarch64-linux-gnu"
	export LD="clang --target=aarch64-linux-gnu"
	export CXX="clang++ --target=aarch64-linux-gnu"
else
	export CC="aarch64-linux-gnu-gcc"
	export LD="aarch64-linux-gnu-ld"
	export AR="aarch64-linux-gnu-ar"
	export CXX="aarch64-linux-gnu-g++"
fi

export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/aarch64-linux-gnu/pkgconfig
export PKG_CONFIG_PATH="$HOME/cunit-install/aarch64/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}

export CROSS_ARCH=arm64
export DPDK_CROSS=aarch64-linux-gnu-
export TARGET="arm64$DPDKCC"

dpkg -i --force-depends ~/download/libpcap0.8-dev_1.5.3-2_arm64.deb

git clone ${CWD}/../../ odp
cd ./odp
./scripts/ci/build_dpdk.sh
DPDKPATH=`cat /tmp/dpdk_install_dir`

./bootstrap
./configure --host=aarch64-linux-gnu --build=x86_64-linux-gnu --with-dpdk-path=${DPDKPATH} \
	--disable-test-cpp ${CONF}
make clean
make -j 8

if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

cd ~ 
rm -rf ${TDIR}
