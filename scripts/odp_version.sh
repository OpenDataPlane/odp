#!/bin/bash

VFILE="platform/linux-generic/include/api/odp/version.h"

GEN=`grep "define ODP_VERSION_API_GENERATION"	${VFILE} | cut -d ' ' -f 3`
MAJ=`grep "define ODP_VERSION_API_MAJOR"	${VFILE} | cut -d ' ' -f 3`
MIN=`grep "define ODP_VERSION_API_MINOR"	${VFILE} | cut -d ' ' -f 3`

echo -n $GEN.$MAJ.$MIN
