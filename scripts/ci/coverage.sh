#!/bin/bash
set -e

# CC LD AR CXX has to be predifubed
#

export PKG_CONFIG_PATH="$HOME/cunit-install/x86_64/lib/pkgconfig:${PKG_CONFIG_PATH}"

CWD=$(dirname "$0")
TDIR=`mktemp -d -p ~`

cd ${TDIR}
echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

git clone ${CWD}/../../ odp
cd ./odp
./bootstrap
./configure \
	CFLAGS="-O0 -coverage $CLFAGS" CXXFLAGS="-O0 -coverage $CXXFLAGS" LDFLAGS="--coverage $LDFLAGS" \
	--enable-debug=full --enable-helper-linux --enable-dpdk --disable-test-perf --disable-test-perf-proc
export CCACHE_DISABLE=1
make -j $(nproc)

# ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

ODP_SCHEDULER=basic    make check
if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

ODP_SCHEDULER=sp       make check
if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

ODP_SCHEDULER=iquery   make check
if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

ODP_SCHEDULER=scalable make check
if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi


bash <(curl -s https://codecov.io/bash) -X coveragepy

cd ~
rm -rf ${TDIR}

umount /mnt/huge
