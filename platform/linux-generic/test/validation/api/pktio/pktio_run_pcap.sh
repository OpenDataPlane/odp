#!/bin/sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2015-2018 Linaro Limited
#

# any parameter passed as arguments to this script is passed unchanged to
# the test itself (pktio_main)

# directories where pktio_main binary can be found:
# -in the validation dir when running make check (intree or out of tree)
# -in the script directory, when running after 'make install', or
# -in the validation when running standalone intree.
# -in the current directory.
# running stand alone out of tree requires setting PATH
PATH=${TEST_DIR}/api/pktio:$PATH
PATH=$(dirname $0):$PATH
PATH=$(dirname $0)/../../../../../../test/validation/api/pktio:$PATH
PATH=.:$PATH

pktio_main_path=$(which pktio_main${EXEEXT})
if [ -x "$pktio_main_path" ] ; then
	echo "running with $pktio_main_path"
else
	echo "cannot find pktio_main${EXEEXT}: please set you PATH for it."
	exit 1
fi

export ODP_PKTIO_TEST_DISABLE_START_STOP=1

PCAP_FNAME=vald.pcap
export ODP_PKTIO_IF0="pcap:out=${PCAP_FNAME}"
export ODP_PKTIO_IF1="pcap:in=${PCAP_FNAME}"
pktio_main${EXEEXT} $*
ret=$?
rm -f ${PCAP_FNAME}
exit $ret
