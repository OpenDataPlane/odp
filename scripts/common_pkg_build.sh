#!/bin/bash

set -e

prepare_tarball() {
	export package=opendataplane

	pushd ${ROOT_DIR}
	./bootstrap
	./configure
	make dist

	version=$(cat ${ROOT_DIR}/.scmversion)

	cp ${package}-${version}.tar.gz ${package}_${version}.orig.tar.gz
	tar xzf ${package}_${version}.orig.tar.gz
}
