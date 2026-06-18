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
	    "shut off" )
		echo "undefine ${domain}: domain is already ${state}"
		;;
	    * )
		# assume this is instantaneous?!?
		RUN sudo virsh destroy ${domain} || true
		;;
	esac
	RUN sudo virsh undefine ${domain} || true
    else
	echo "undefine ${domain}: no such domain"
    fi
done
