#!/bin/sh
set -u

# Send a ping packets using fping and then wait for a reply.

usage() {
	if test $# -lt 2; then
		cat <<EOF
Usage:

    $0 --(up|down|fire-and-forget|lossy) <options> <destination>" 1>&2

Send ping message using fping.  Where:

  --up			expect the remote end to be up (wait a long while)
  --down		expect the remote end to be down (wait a short while)
  --fire-and-forget	do not wait for reply (actually waits n+1 seconds)
  --lossy 		expect non zero response and probably some loss

IPv4:
Packet sizes (padding is always 0). The default is 56-bytes which,
when combined with the 8-byte IPv4 ICMP header, works out to 64-bytes ICMP
message. The resulting IPv4 packet will be 84-bytes, which is what IPsec
, e.g Linux xfrm ip -s xfrm state, counts as bytes out and in.
When using the tunnel mode, the Encpsulated ESP message will be about 120-bytes.
And the encapsulated IP packet size 140-bytes. And to be complete Ethernet
frame size 154 bytes.

  --small		send a small 12-byte packet, should not compress/fragment
  --medium		send a medium 1k packet, should compress)
  --large		send a large 8k packet, should fragment and/or compress

Other options:

  --error		expect a strange error code
  --runcon		wrap fping command in specified runconn command
EOF
		exit 1
	fi
}

function err() {
        local exitcode=$1
        shift
        echo "ERROR: $@" >&2
        exit $exitcode
}

verbose=${verbose-''}
if [ "${verbose}" = "yes" ]; then
	set -x
fi

op=up
args=
count=1
interval=5 #long for ipv4 and just enough for ipv6 ND timeout
FPING=${fping-fping}
wait=5

OPTIONS=$(getopt -o I: --long up,down,lossy:,src:,help, -- "$@")
if [ $? -gt 0 ]; then
    err 4 "Error calling getopt"
fi
eval set -- "$OPTIONS"

while true; do
    case "$1" in
	--up )
	    op=up
	    interval=${timeout}
	    shift
	    ;;
	--down )
	    op=down
	    timeout=1 # may fail for delayed IPv6 ND timeout on the receiver side.
	    shift
	    ;;
	--lossy )
	    op=up
	    count=$2
	    wait=$(expr 1 + ${count})
	    interval=1
	    shift 2
	    ;;
	--fire-and-forget | --forget )
	    # XXX: 0 doesn't seem to do anything?
	    timeout=1
	    shift 2
	    ;;
	--error )
	    wait=1
	    shift 2
	    ;;
	--small )
	    size=12
	    shift 2
	    ;;
	--medium )
	    size=1000
	    shift 2
	    ;;
	--large )
	    size=8000
	    shift 2
	    ;;
	--ethernet )
	    size=1480
	    shift 2
	    ;;
	--timeout )
	    timeout=$2
	    shift 2
	    ;;
	-I| --src ) # -I in fping --src
	    src=$2
	    shift 2
	    ;;

	-- ) shift; break ;; # last argument destination

	*)
	    echo "Unrecognized custom option: $1" 1>&2
 	    exit 1
 	    ;;
    esac
done

shift $((OPTIND - 1))

if [ $# -ne 1 ] ; then
    echo "too many parameters: $@"
    exit 1
fi

timeout=" --timeout ${wait}s"
size=${size:+--size ${size}}
src=${src:+--src ${src}}

# Record the fping command that will run (the secret sauce used to
# invoke fping is subject to change, it is hidden from the test
# results).

fping="${FPING} -n -c ${count} ${timeout} ${size} ${args} ${src} "$@""

echo ==== cut ====
echo "${fping}"
echo ==== tuc ====

# Run the fping command, capturing output and exit code.

output=$(${fping} 2>&1)
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
    up-forget | down-forget) echo fired and forgotten ; exit 0 ;;
    up-up | down-down | up-lossy ) echo ${result} ; exit 0 ;;
    down-up | up-down )
	echo ${result} UNEXPECTED
	echo "# ${FPING}"
	echo "${output}"
	exit 1
	;;
    down-lossy )
	# fping output
	loss_pc=$(echo ${output} | sed -e 's/\(.*\)\(xmt\/rcv\/%loss = \)\([0-9]*\/\)\([0-9]*\/\)\([0-9]*\)\(%.*\)/\5/g;')
	if [ "${loss_pc}" = 100 ] ; then
		echo 100% loss UNEXPECTED
		echo "$output"
	else
		echo up ; #down is up with is losses.
		exit 0;
	fi
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
