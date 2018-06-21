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
DPDKPATH=`cat /tmp/dpdk_install_dir`

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure --host=x86_64-linux-gnu --build=x86_64-linux-gnu ${CONF} \
	--with-dpdk-path=${DPDKPATH}

make clean
make -j 8
# Tell some time sensative ODP test that they can be skipped due to not
# isolated environment.
export CI="true"
make check

if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

cd ~
rm -rf ${TDIR}

umount /mnt/huge

