#!/bin/sh

if test $# -ne 3 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <rutdir> <commit> <directory>

Generate enough of a summary.json file for the web page to build a
TestResult().  Note that the times are set to zero aka epoch.

EOF
    exit 1
fi

bindir=$(realpath $(dirname $0))
rutdir=$1 ; shift
commit=$1 ; shift
directory=$1 ; shift

jq --null-input \
   --arg commit "${commit}" \
   --arg directory "${directory}" \
   '
{
  start_time: null,
  directory: $directory,
  current_time: null,
  total: 0,
  hash: $commit,
}'
