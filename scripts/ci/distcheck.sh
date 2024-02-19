#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

cd "$(dirname "$0")"/../..
./bootstrap
./configure ${CONF}

# Ignore possible failures there because these tests depends on measurements
# and systems might differ in performance.
export CI="true"

# Additional configure flags for distcheck
export DISTCHECK_CONFIGURE_FLAGS="${CONF}"

make distcheck
