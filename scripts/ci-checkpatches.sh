#!/usr/bin/env bash

set -o xtrace

PATCHES=$1
echo "Run checkpatch for ${PATCHES}"
# Generate patches provided with $1. If commit range is not available validate
# only the latest commit.

if [ "$PATCHES" = "" ]; then
	git format-patch -1 -M HEAD;
else
	git format-patch ${PATCHES}
fi

perl ./scripts/checkpatch.pl *.patch;
exit $?
