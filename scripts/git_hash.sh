#!/bin/bash

if [ -z ${1} ]; then
	echo "should be called with a path"
	exit
fi
ROOTDIR=${1}

CUSTOM_STR=${CUSTOM_STR:-https://git.linaro.org/lng/odp.git}
if [ -d ${ROOTDIR}/.git ]; then
	hash=$(git --git-dir=${ROOTDIR}/.git describe | tr -d "\n")
	if [[ $(git --git-dir=${ROOTDIR}/.git diff --shortstat 2> /dev/null \
		| tail -n1) != "" ]]; then
		dirty=-dirty
	fi

	echo -n "'${CUSTOM_STR}' (${hash}${dirty})">${ROOTDIR}/.scmversion
fi

cat ${ROOTDIR}/.scmversion
