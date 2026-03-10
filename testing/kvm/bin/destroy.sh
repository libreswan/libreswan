#!/bin/sh

set -e

if test "$#" -lt 1 ; then
    cat <<EOF
Usage:
  $0 <domain> ...
uses virsh to destroy the domains
EOF
    exit 0
fi

RUN() {
    echo + "$@"
    "$@"
}

for domain in "$@" ; do
    if state=$(sudo virsh domstate ${domain} 2>&1); then
	case "${state}" in
	    "running" | "in shutdown" | "paused" )
		RUN sudo virsh destroy ${domain} || true
		;;
	    * )
		echo "Ignoring ${state} domain ${domain}"
		;;
	esac
    else
	echo "No domain ${domain}"
    fi
done
