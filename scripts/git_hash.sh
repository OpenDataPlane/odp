#!/bin/bash

repo=https://git.linaro.org/lng/odp.git
hash=$(git describe | tr -d "\n")
if git diff-index --name-only HEAD &>/dev/null ; then
	dirty=-dirty
fi

echo -n "'${repo}' (${hash}${dirty})"
