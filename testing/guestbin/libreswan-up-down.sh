#!/bin/sh

set -eu

# Its assumed that this happens very very fast.

if test $# -eq 0 ; then
    cat <<EOF > /dev/stderr
Usage:

    $0 <config> <ping-param>...

Add, up, ping, down, delete <config>.

Use repeatedly to test algorithm variations that should work.

EOF
   echo "Usage: $0 <config> <ping-params>" 1>&2
   exit 1
fi

bindir=$(dirname $0)
config=$1 ; shift

ipsec auto --add ${config}

# can't trust exit code; for moment preserve old behaviour - should be
# always deleting

if ipsec auto --up ${config} && ipsec whack --trafficstatus | grep "${config}" >/dev/null; then
    ${bindir}/wait-until-alive "$@"
    ipsec auto --down ${config}
    ipsec auto --delete ${config}
else
    ipsec auto --delete ${config} > /dev/null # silent for now
fi
