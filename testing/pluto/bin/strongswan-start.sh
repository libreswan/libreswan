#!/bin/sh

service strongswan start

seconds=0
while test ${seconds} -lt 10 ; do
    status=$(strongswan status)
    case "${status}" in
	*"Security Associations"* )
	    # should this display the output from "strongswan
	    # status[all]"
	    echo "${status}"
	    echo strongSwan started
	    exit 0
	    ;;
    esac
    seconds=$(expr ${seconds} + 1)
    sleep 1
done

cat <<EOF >/dev/stderr
strongSwan did not start after ${seconds} seconds.
EOF

exit 1
