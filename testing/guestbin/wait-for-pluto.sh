#!/bin/sh

if test $# -eq 0 ; then
    cat <<EOF
Usage:
  $0 [ --timeout <seconds> ] <match>
Wait for pluto's logs to contain <match>
EOF
    exit 1
fi

timeout=
while test $# -gt 0 ; do
    case $1 in
	--timeout )
	    timeout="--timeout $2"
	    shift
	    shift
	    ;;
	* )
	    pattern="$1"
	    shift
	    ;;
    esac
done

../../guestbin/wait-for.sh ${timeout} --match "${pattern}" -- cat /tmp/pluto.log
