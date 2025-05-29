#!/bin/sh

set -e

run() (
    set -x ; "$@"
)

for file in "$@" ; do
    domain=$(basename ${file})
    if state=$(sudo virsh domstate ${domain} 2>&1); then
	case "${state}" in
	    "running" | "in shutdown" | "paused" )
		run sudo virsh destroy ${domain} || true
		run sudo virsh undefine ${domain}
		;;
	    "shut off" )
		run sudo virsh undefine ${domain}
		;;
	    * )
		echo "Unknown state ${state} for ${domain}"
		;;
	esac
    else
	echo "No domain ${domain}"
    fi
    # only delete domain stuff; other stuff like .ks files needs to
    # stay around
    rm -vf ${file}.qcow2
    rm -vf ${file}
done
