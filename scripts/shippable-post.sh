#!/bin/sh

wget https://raw.githubusercontent.com/shawnliang/cunit-to-junit/master/cunit-to-junit.xsl

for FILE in `find  ./test ./platform/ -name  "*.xml"`; do
	bname="`basename $FILE`";
	xsltproc --novalid cunit-to-junit.xsl "$FILE" > \
		"$SHIPPABLE_BUILD_DIR/shippable/testresults/${bname}"
done
