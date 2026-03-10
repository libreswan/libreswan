#!/bin/sh

set -e

if test "$#" -lt 1 ; then
    cat <<EOF
Usage:
  $0 <domain> ...
uses virsh to shutdown the domains
EOF
    exit 0
fi

RUN() {
    echo + "$@" 1>&2
    "$@"
}

for domain in "$@" ; do
    if state=$(sudo virsh domstate ${domain} 2>&1); then
	case "${state}" in
	    "running" | "in shutdown" | "paused" )
		# docs don't guarentee that "shutdown" will wait
		RUN sudo virsh shutdown ${domain} < /dev/null || true
		# attach console and wait for it to close; as a bonus,
		# gives nice visual.
		RUN sudo virsh console --force ${domain} || true
		;;
	    * )
		echo "shutdown: ignoring ${state} domain ${domain}"
		;;
	esac
    else
	echo "shutdown: no domain ${domain}"
    fi
done
