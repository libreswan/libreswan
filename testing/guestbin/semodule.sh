#!/bin/sh

set -eu

if test $# -ne 1 ; then
    echo "Usage: $0 <ipsecspd.te>" 1>&2
    exit 1
fi

spd=$(basename $1 .te)
te=${spd}.te
pp=${spd}.pp

if test ! -r ${te} ; then
    echo "${te} not found" 1>&2
    exit 1
fi

(
    cd OUTPUT
    rm -f ${pp} ${te}
    ln -s ../${te}
    make -f /usr/share/selinux/devel/Makefile ${pp}
)

semodule -i OUTPUT/${pp}
echo ${pp} installed
