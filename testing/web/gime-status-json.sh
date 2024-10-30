#!/bin/sh

if test $# -lt 3 ; then
    cat >> /dev/stderr <<EOF

Usage:

    $0 <directory> <start_time> <details> ...

Print status.json on stdout.

EOF
    exit 1
fi

bindir=$(cd $(dirname $0) && pwd)
directory=$1 ; shift
start_time=$1 ; shift

jq --null-input \
   --arg details "$*" \
   --arg directory "${directory}" \
   --arg start_time "${start_time}" \
   '
{}
| .current_time = (now|todateiso8601)
| .start_time = $start_time
| .directory = $directory
| .details = $details
'
