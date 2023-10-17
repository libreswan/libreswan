#!/bin/sh

if test $# -ne 2 ; then
    cat <<EOF 1>&2
Usage:
	$(basename $0) <src-file> <mount-point>
Copy <src-file> to /tmp and then bind mount it on <mount-point>
For instance:
	$(basename $0) /etc/hosts /etc/hosts
will copy /etc/hosts to /tmp, giving it a magical name,  and then
bind-mount it as /etc/hosts
EOF
    exit 1
fi

set -eu

src=$1
tmp=/tmp/$(basename ${src}).$(hostname).$(basename $PWD) # assume this is the test-directory
mount=$2

if mount | grep " ${mount} " > /dev/null ; then
    umount ${mount}
fi

echo ${src} ${tmp} ${mount}
cp ${src} ${tmp}
mount --bind ${tmp} ${mount}
