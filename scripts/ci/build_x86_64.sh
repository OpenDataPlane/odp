#!/bin/bash
set -e

if [ "${CC#clang}" != "${CC}" ] ; then
	export CXX="clang++"
fi

exec "$(dirname "$0")"/build.sh
