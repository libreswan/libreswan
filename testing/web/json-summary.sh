#!/bin/sh

if test $# -ne 1 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <start-date>

Generate just enough of a summary.json file to fool the top-level
summary page into thinking something happened.

EOF
    exit 1
fi

start_time=$1 ; shift

jq --null-input \
   --arg start "${start_time}" \
   '{
  start_time: $start,
  end_time: (now|todateiso8601),
}'
