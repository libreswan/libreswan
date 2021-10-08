#!/bin/sh

set -eu

# Its assumed that this happens very very fast.

if test $# -eq 0 ; then
    cat <<EOF > /dev/stderr
Usage:

    $0 <config> [--up|--down|--alive] <ping-param>...

Add, up, ping[s], down, delete <config>:

   --up expect a single ping to work
   --down don't expect success (skip ping)
   --alive expect the remote to eventually come on line

Use repeatedly to test algorithm variations that should work.

EOF
   exit 1
fi

bindir=$(dirname $0)
config=$1 ; shift

expect=
case "$1" in
    --up) expect=up ; shift ;;
    --down) expect=down ; shift ;;
    --alive) expect=alive ; shift ;;
esac

ipsec auto --add ${config}

# Can't assume a 0 exit code code returned by --up means that the
# connection is up; hence also look to see if there's traffic status.

# down+delete is redundant; should always delete unconditionally

if ipsec auto --up ${config} && ipsec whack --trafficstatus | grep "${config}" >/dev/null; then
    case "${expect}" in
	"" | up )
	    ${bindir}/ping-once.sh --up "$@"
	    ;;
	alive )
	    # Massive hack for IKEv1: quick-mode doesn't wait for a
	    # response to the last message sent so need to give the
	    # responder time to digest it.
	    sleep 5
	    ${bindir}/wait-until-alive "$@"
	    ;;
	* )
	    echo ${expect} UNEXPECTED
	    ;;
    esac
    ipsec auto --down ${config}
    ipsec auto --delete ${config}
else
    case "${expect}" in
	"" | down ) ;;
	* ) echo ${expect} UNEXPECTED ;;
    esac
    ipsec auto --delete ${config} > /dev/null # silent for now
fi
