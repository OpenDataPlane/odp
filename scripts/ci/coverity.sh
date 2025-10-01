#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"/../..
./bootstrap
./configure --enable-debug=full

make clean

cov-build --dir cov-int make -j $(nproc)

tar czf odp-coverity.tgz cov-int

curl --form token="${COVERITY_TOKEN}" \
  --form email="${COVERITY_EMAIL}" \
  --form file=@odp-coverity.tgz \
  --form version="${GITHUB_SHA}" \
  --form description="GitHub Actions ODP Coverity Build" \
  "https://scan.coverity.com/builds?project=${COVERITY_PROJECT}"
