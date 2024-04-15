#!/bin/sh

set -eu

if test $# -lt 1 -a $# -gt 1 ; then
    cat <<EOF
Usage:
  $0 <packet-number>
Waits for outbound <packet-number>.
EOF
    exit 1
fi

../../guestbin/wait-for.sh --match 'IMPAIR: blocking outbound message '${1}'$'  -- cat /tmp/pluto.log
