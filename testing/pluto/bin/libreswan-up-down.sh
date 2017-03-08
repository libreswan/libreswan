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
ipsec auto --up ${config}
${bindir}/wait-until-alive "$@"
ipsec auto --down ${config}
ipsec auto --delete ${config}
