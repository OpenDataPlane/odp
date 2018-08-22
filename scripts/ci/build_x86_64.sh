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
./configure ${CONF} \
	--enable-dpdk

make -j 8
# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"
make check

if [ $? -ne 0 ]; then
  find . -name "*.trs" | xargs grep -l '^.test-result. FAIL' | while read trs ; do echo FAILURE detected at $trs; cat ${trs%%.trs}.log ; done
fi

cd ~
rm -rf ${TDIR}

umount /mnt/huge

