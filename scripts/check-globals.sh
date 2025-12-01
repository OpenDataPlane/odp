#!/usr/bin/env bash
#
# Check that global symbols in a static library conform to a given regex.
# Only static library is checked, since libtool -export-symbols-regex
# takes care of dynamic libraries.
#
# Required variables:
# LIBTOOL               Path to libtool.
# NM                    Path to nm.
# LIB                   Library directory.
# lib_LTLIBRARIES       Library .la file.
# CHECK_GLOBALS_REGEX   Global symbols matching this regex are accepted.
#
set -o errexit

tmpfile=$(mktemp)

# get $objdir
$LIBTOOL --config > $tmpfile
. $tmpfile

# get $old_library (static library name)
. $lib_LTLIBRARIES

echo "$old_library: Checking global symbols, regex: $CHECK_GLOBALS_REGEX"

# get a list of symbols that are global, are not undefined or weak, and
# do not match the regex
$NM -g --defined-only $LIB/$objdir/$old_library | \
        egrep " [uA-T] " | egrep -v "$CHECK_GLOBALS_REGEX" | tee $tmpfile

num=$(cat $tmpfile | wc -l)
rm -f $tmpfile

if [ "$num" != "0" ]; then
        echo "$old_library: ($num non-matching symbols)"
        false
fi
