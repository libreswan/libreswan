#!/bin/sh

set -e

run() {
    echo -n "$@"": "
    "$@"
}

for file in "$@" ; do
    network=$(basename ${file})
    if sudo virsh net-info ${network} >/dev/null 2>&1 ; then
	run sudo virsh net-destroy ${network}
	run sudo virsh net-undefine ${network}
    fi
    rm -f ${file}
    rm -f ${file}.*
done
