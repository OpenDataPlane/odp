#!/bin/bash


cat <<EOF > $SHIPPABLE_BUILD_DIR/shippable/testresults/test_results.xml

<?xml version="1.0" ?>
<testsuites errors="1" failures="2" skipped="3" tests="6" time="123.345">
	<testsuite errors="4" failures="2" name="my test suite" skipped="0" tests="1" time="123.345">
		<testcase classname="some.class.name" name="Test1" time="123.345000">
			<system-out>I am stdout!</system-out>
			<system-err>I am stderr!</system-err>
		</testcase>
	</testsuite>
</testsuites>
EOF
