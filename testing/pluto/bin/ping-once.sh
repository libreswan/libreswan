#!/bin/sh

# Send a single ping packet and then wait for a reply.

if test $# -lt 2; then
    cat <<EOF
Usage:

    $0 --up|--down|--forget [-I <interface>] <destination>" 1>&2

Send one ping packet.  Options:

  --up      expect the remote end to be up (wait a long while)
  --down    expect the remote end to be down (wait a short while)
  --forget  do not wait around (ok 1 seconds)
            XXX: is this useful or should --down|--up be used

EOF
    exit 1
fi

op=$1 ; shift

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

case "${op}" in
    --up)
	wait=5
	;;
    --down)
	wait=1
	;;
    --forget)
	# XXX: 0 doesn't seem to do anything?
	wait=1
	;;
    *)
	echo "Unrecognized option: ${op}" 1>&2
	exit 1
	;;
esac

# run the ping command, map well known exit codes onto names.
ping="ping -q -n -c 1 -i $(expr 1 + ${wait}) -w ${wait} "$@""
output=$(${ping})
status=$?
case "${status}" in
    0) status=up ;;
    1) status=down ;;
esac

# So kernel log lines are not lost, only print output after ping
# completes.
echo ==== cut ====
echo "${ping}"
echo "${output}"
echo ==== tuc ====

case "${status}${op}" in
    up--up | down--down ) echo ${status} ; exit 0 ;;
    down--up | up--down ) echo ${status} unexpected ; exit 1 ;;
    up--forget | down--forget ) exit 0 ;;
    * ) echo $0: unexpected status ${status} 1>&2 ; exit ${status} ;;
esac
