#!/bin/sh

# Send a single ping packet and then wait for a reply.

if test $# -lt 2; then
    cat <<EOF
Usage:
    $0 --up|--down|--fire-and-forget|--error [-I <interface>] <destination>" 1>&2
Send one ping packet.  Options:
  --up			expect the remote end to be up (wait a long while)
  --down		expect the remote end to be down (wait a short while)
  --fire-and-forget	do not wait for reply (actually waits 1 seconds)
  --error		expect a strange error code
EOF
    exit 1
fi

op=
runcon=

while test $# -gt 0 && expr "$1" : "--" > /dev/null; do
    case "$1" in
	--up)
	    op=up
	    wait=5  # a long time
	    ;;
	--down)
	    op=down
	    wait=1  # a short time
	    ;;
	--fire-and-forget|--forget)
	    # XXX: 0 doesn't seem to do anything?
	    op=forget
	    wait=1
	    ;;
	--error)
	    op=error
	    wait=1
	    ;;
	--runcon)
	    shift
	    runcon=$1
	    ;;
	--*)
	    echo "Unrecognized option: ${op}" 1>&2
	    exit 1
	    ;;
	*)
	    break
	    ;;
    esac
    shift
done

if test -z "${op}" ; then
    echo "Missing --<operation>" 1>&2
    exit 1
fi

# Record the ping command that will run (the secret sauce used to
# invoke ping is subject to change, it is hidden from the test
# results).
#
# Ping options:
#
# -q              be quiet
# -n              numeric only (don't touch DNS)
# -c <count>      send <count> packets (always one)
# -w <deadline>   give up after <deadline> seconds
# -i <interval>   wait <interval> seconds between packets
#
# To prevent more than one packet going out, the ping <interval> must
# be greater than the <deadline>.

ping="ping -q -n -c 1 -i $(expr 1 + ${wait}) -w ${wait} "$@""
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
    up-up | down-down )       echo ${result} ;                         exit 0 ;;
    down-up | up-down )       echo ${result} UNEXPECTED ;              exit 1 ;;
    up-forget | down-forget ) echo fired and forgotten ;               exit 0 ;;
    error-error )             echo "${output}" | sed -e 's/ping: //' ; exit 0 ;;
    * ) echo unexpected status ${status} ; echo ${output} ;              exit 1 ;;
esac
