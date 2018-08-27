#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure \
	CFLAGS="-O0 -coverage $CLFAGS" CXXFLAGS="-O0 -coverage $CXXFLAGS" LDFLAGS="--coverage $LDFLAGS" \
	--enable-debug=full --enable-helper-linux --enable-dpdk --disable-test-perf --disable-test-perf-proc
export CCACHE_DISABLE=1
make -j $(nproc)

echo 1000 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Ignore possible failures there because these tests depends on measurements
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

umount /mnt/huge
