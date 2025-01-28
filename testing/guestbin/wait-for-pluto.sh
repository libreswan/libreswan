#!/bin/sh

if test $# -eq 0 ; then
    cat <<EOF
Usage:
  $0 [ --timeout <seconds> ] <match>
Wait for pluto's non-debug logs to contain <match>
EOF
    exit 1
fi

timeout=30
while test $# -gt 0 ; do
    case $1 in
	--timeout )
	    timeout="$2"
	    shift
	    shift
	    ;;
	* )
	    regex="$1"
	    shift
	    ;;
    esac
done

count=0
while count=$((count + 1)) && test ${count} -le ${timeout} ; do
    input=$(grep -v -e '|' /tmp/pluto.log)
    if output=$(echo "${input}" | grep "${regex}"); then
	echo "${output}"
	exit 0
    fi
    sleep 1
done

echo timeout waiting ${timeout} seconds for "${regex}" 1>&2
echo "${input}" | tail -100 | sed -e 's/^/output: /'
exit 1
