#!/bin/bash

set -e

run() {
    echo -n "$@"": "
    "$@"
}

for file in "$@" ; do
    network=$(basename ${file})
    if info=$(sudo virsh net-info ${network} 2>/dev/null) ; then
	if [[ "${info}" =~ Active:' '*yes ]] ; then
	    run sudo virsh net-destroy ${network}
	fi
	if [[ "${info}" =~ Persistent:' '*yes ]] ; then
	    run sudo virsh net-undefine ${network}
	fi
    fi
    rm -f ${file}
    rm -f ${file}.*
done
