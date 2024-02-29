#!/bin/sh

set -e

run() {
    echo -n "$@"": "
    "$@"
}

for file in "$@" ; do
    domain=$(basename ${file})
    if state=$(sudo virsh domstate ${domain} 2>&1); then
	case "${state}" in
	    "running" | "in shutdown" | "paused" )
		run sudo virsh destroy ${domain}
		run sudo virsh undefine ${domain} --managed-save --snapshots-metadata
		;;
	    "shut off" )
		run sudo virsh undefine ${domain} --managed-save --snapshots-metadata
		;;
	    * )
		echo "Unknown state ${state} for ${domain}"
		;;
	esac
    else
	echo "No domain ${domain}"
    fi
    rm -f ${file}.qcow2
    rm -f ${file}
done
