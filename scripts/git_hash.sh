#!/bin/bash

if [ -z ${1} ]; then
	echo "should be called with a path"
	exit
fi
ROOTDIR=${1}

CUSTOM_STR=${CUSTOM_STR:-https://git.linaro.org/lng/odp.git}
if [ -d ${ROOTDIR}/.git ]; then
	hash=$(git describe | tr -d "\n")
	if git diff-index --name-only HEAD &>/dev/null ; then
		dirty=-dirty
	fi

	echo -n "'${CUSTOM_STR}' (${hash}${dirty})">${ROOTDIR}/.scmversion
fi

cat ${ROOTDIR}/.scmversion
