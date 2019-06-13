#!/bin/bash
#
# Copyright (c) 2019, Nokia
# All rights reserved.
#
# SPDX-License-Identifier:	BSD-3-Clause
#

# Skip IPsec example tests when there's no OpenSSL.
if [ -n "$WITH_OPENSSL" ] && [ ${WITH_OPENSSL} -eq 0 ]; then
echo "Crypto not supported. Skipping."
exit 77
fi

# Absolute path to the example binary. This is needed during distcheck, which
# keeps scripts and binaries in different directories (scripts are not copied
# into the distribution directory).
export IPSEC_EXAMPLE_PATH=$(pwd)/../../../example/ipsec

declare -i RESULT=0

pushd $(dirname $0)/../../../../example/ipsec

./odp_ipsec_run_simple.sh
RESULT+=$?

./odp_ipsec_run_esp_out.sh
RESULT+=$?

popd

exit ${RESULT}
