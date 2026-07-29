#!/bin/sh

# Provided nothing goes wrong, this script should have no output.
# That way, the sanitizers and the reference output don't have to deal
# with moving targets.

hostname=$(hostname)
pidfile=/run/strongswan/charon.pid

# avoid systemd so this works in namespaces
# /bin/systemctl start strongswan.service

start_strongswan()
{
    /usr/sbin/strongswan start > /dev/null 2>&1
    seconds=0
    while test ${seconds} -lt 10 ; do
	status=$(strongswan status)
	case "${status}" in
	    *"Security Associations"* )
		# should this display the output from "strongswan
		# status[all]"
		exit 0
		;;
	esac
	seconds=$(expr ${seconds} + 1)
	sleep 1
    done
}

start_charon()
{
    /usr/bin/charon-systemd > OUTPUT/$(hostname).charon.log 2>&1 &
    pid=$!
    echo ${pid} > ${pidfile}

    # wait for it to come ready
    seconds=0
    while test ${seconds} -lt 10 ; do
	if swanctl --stats > /dev/null 2>&1 ; then
	    exit 0
	fi
	seconds=$(expr ${seconds} + 1)
	sleep 1
    done
}

if test -r /etc/strongswan/ipsec.conf ; then
    start_strongswan
else
    start_charon
fi

cat <<EOF >/dev/stderr
strongSwan did not start after ${seconds} seconds.
EOF

exit 1
