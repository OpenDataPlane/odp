#!/bin/bash

PATCHES=$1
echo "Run checkpatch for ${PATCHES}"
# Generate patches provided with $1.
# In case of force push and range is broken
# validate only the latest commit if it's not merge commit.
git format-patch ${PATCHES}
if [ $? -ne 0 ]; then
	git show --summary HEAD| grep -q '^Merge:';
	if [ $? -ne 0 ]; then
		git format-patch HEAD^;
		perl ./scripts/checkpatch.pl *.patch;
	fi;
else
	perl ./scripts/checkpatch.pl *.patch;
fi
