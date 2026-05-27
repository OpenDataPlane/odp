#!/bin/bash
set -e

echo 1500 | tee /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

"`dirname "$0"`"/build_${ARCH}.sh

cd "$(dirname "$0")"/../..

export CI="true"

test/validation/api/crypto/crypto_main
test/validation/api/ipsec/ipsec_sync.sh
test/validation/api/ipsec/ipsec_async.sh
test/validation/api/ipsec/ipsec_inline_in.sh
test/validation/api/ipsec/ipsec_inline_out.sh

umount /mnt/huge
