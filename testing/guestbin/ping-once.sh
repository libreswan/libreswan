#!/bin/sh

# Send a single ping packet and then wait for a reply.

if test $# -lt 2; then
    cat <<EOF

Usage:

    $0 --(up|down|fire-and-forget) <options> <destination>" 1>&2

Send one ping packet.  Where:

  --up			expect the remote end to be up (wait a long while)
  --down		expect the remote end to be down (wait a short while)
  --fire-and-forget	do not wait for reply (actually waits 1 seconds)

Packet sizes (padding is always 0).  The default is 56-bytes which,
when combined with the 8-byte IPv4 ICMP header, works out to 64-byte
message.

  --small		send a small 12-byte packet, should not compress/fragment
  --medium		send a medium 1k packet, should compress)
  --large		send a large 8k packet, should fragment and/or compress

Other options:

  --error		expect a strange error code
  --runcon		wrap ping command in specified runconn command
EOF
    exit 1
fi

op=
runcon=
args=

while test $# -gt 0 && expr x"$1" : x"-" > /dev/null; do
    case "$1" in
	--up )
	    op=up
	    wait=5  # a long time
	    ;;
	--down )
	    op=down
	    wait=1  # a short time
	    ;;
	--fire-and-forget | --forget )
	    # XXX: 0 doesn't seem to do anything?
	    op=forget
	    wait=1
	    ;;
	--error )
	    op=error
	    wait=1
	    ;;
	--runcon )
	    shift
	    runcon=$1
	    ;;
	--small )
	    size=12
	    ;;
	--medium )
	    size=1000
	    ;;
	--large )
	    size=8000
	    ;;
	--*)
	    echo "Unrecognized custom option: $1" 1>&2
 	    exit 1
 	    ;;
	-I ) # -I INTERFACE, actually source
	    shift
	    interface=$1
	    ;;
	-*)
	    echo "Unrecognized common option: $1" 1>&2
	    exit 1
	    ;;
	*)
	    break
	    ;;
    esac
    shift
done

if test -z "${op}" ; then
    echo "missing --(up|down|fire-and-forget)" 1>&2
    exit 1
fi

if test $# -ne 1 ; then
    echo "too many parameters: $@"
    exit 1
fi

# use a heuristic to figure out ping vs ping6

case $(uname -s) in
    *BSD )
	ping=fping
	;;
    Linux )
	case "$@" in
	    *:* )
		ping=fping
		;;
	    * )
		ping=ping
		;;
	esac
    ;;
esac

case ${ping} in
    fping )
	interface=${interface:+--src ${interface}}
	timeout=" --timeout ${wait}s"
	size=${size:+--size ${size}}
	nodns=
	;;
    ping )
	interface=${interface:+-I ${interface}}
	# To prevent more than one packet going out, specify a ping
	# <interval> greater than the wait <deadline>.
	timeout=" -i $(expr 1 + ${wait}) -w ${wait}"
	size=${size:+-s ${size} -p 00}
	nodns=-n
	;;
esac

# Record the ping command that will run (the secret sauce used to
# invoke ping is subject to change, it is hidden from the test
# results).

ping="${ping} ${nodns} -c 1 ${timeout} ${size} ${args} ${interface} "$@""
if test -n "${runcon}" ; then
    ping="runcon ${runcon} ${ping}"
fi

echo ==== cut ====
echo "${ping}"
echo ==== tuc ====

# Run the ping command, capturing output and exit code.  To prevent a
# kernel log line that is emitted part way through the ping from being
# 'cut', ping's 'cut' output is only displayed after the ping has
# finished.

output=$(${ping} 2>&1)
status=$?
case "${status}" in
    0) result=up ;;
    1) result=down ;;
    2) result=error ;;
    *) result=${status} ;;
esac

echo ==== cut ====
echo "${output}"
echo ==== tuc ====

case "${result}-${op}" in
    up-forget | down-forget ) echo fired and forgotten ; exit 0 ;;
    up-forget | down-forget ) echo fired and forgotten ; exit 0 ;;
    up-up | down-down )       echo ${result} ; exit 0 ;;
    down-up | up-down )
	echo ${result} UNEXPECTED
	echo "# ${ping}"
	echo "${output}"
	exit 1
	;;
    error-error )
	echo "${output}" | sed -e 's/ping: //' -e 's/ping6: //' -e 's/fping: //'
	exit 0
	;;
    * )
        echo unexpected status ${status}
	echo "# ${ping}"
	echo "${output}"
	exit 1 ;;
esac
