#!/bin/sh

exec > /tmp/rc.local.txt 2>&1
set -x

hostname=$(hostname)
echo hostname: ${hostname}
if test -z "${hostname}"; then
    echo "ERROR: Failed to find our swan hostname based on the mac match knownlist " 1>&2
    exit 1
fi

if test ${hostname} != swanbase; then
    rm -vf /etc/rc.d/rc.local
fi
