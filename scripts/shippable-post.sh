#!/bin/sh

wget https://raw.githubusercontent.com/shawnliang/cunit-to-junit/master/cunit-to-junit.xsl

mkdir -p "$SHIPPABLE_BUILD_DIR/shippable/testresults"

SCHED=${1:-default}
echo $SCHED

for FILE in `find  ./test ./platform/ -name  "*.xml"`; do
	bname="`basename $FILE`";
	echo Processing $FILE as ${SCHED}-${bname}
	xsltproc --novalid cunit-to-junit.xsl "$FILE" > \
		"$SHIPPABLE_BUILD_DIR/shippable/testresults/${SCHED}-${bname}"
done
