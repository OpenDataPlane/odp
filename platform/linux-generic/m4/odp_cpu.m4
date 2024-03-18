# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021 Nokia
#

##########################################################################
# Set ODP_CACHE_LINE_SIZE define
##########################################################################
# Currently used only for aarch64
if test "${ARCH_DIR}" = "aarch64"; then
	cache_line_size=64
	# Use default cache size if cross-compiling
	if test $build = $host; then
		cpu_implementer=""
		cpu_part=""

		AC_PROG_GREP
		AC_PROG_SED
		while read line; do
			if echo $line | $GREP -q "CPU implementer"; then
				cpu_implementer=`echo $line | $SED 's/.*\:\s*//'`
			fi
			if echo $line | $GREP -q "CPU part"; then
				cpu_part=`echo $line | $SED 's/.*\:\s*//'`
			fi
		done < /proc/cpuinfo

		# Cavium
		if test "$cpu_implementer" == "0x43"; then
			# ThunderX2 (0x0af) 64B, others 128B
			if test "$cpu_part" == "0x0af"; then
				cache_line_size=64;
			else
				cache_line_size=128;
			fi
		fi
	fi
	AC_DEFINE_UNQUOTED([_ODP_CACHE_LINE_SIZE], [$cache_line_size],
			   [Define cache line size])
fi
