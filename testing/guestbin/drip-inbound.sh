#!/bin/sh

set -eu

if test $# -lt 1 -a $# -gt 2 ; then
    cat <<EOF
Usage:
  $0 <packet-number> [ <pattern> ]
combines the operations:
  - wait for <packet-number> to arrive
  - release <packet-number>
  - wait for <pattern> (when specified)
Useful when stepping messages through pluto
EOF
    exit 1
fi

../../guestbin/wait-for-inbound.sh ${1}

ipsec whack --impair drip_inbound:${1}

if test $# -ge 2 ; then
    ../../guestbin/wait-for.sh --match "${2}" -- cat /tmp/pluto.log
fi
