#!/bin/sh

set -eu

NNTOALL() {
    local h=$1
    local f=$2
    echo "# ${h} $(basename ${f})"
    echo
    sed -e "s/^/${h}# /" ${f}
    echo
}

for f in $1/0*.sh ; do
    h=$(case $f in
	    *east*) echo east ;;
	    *west* ) echo west ;;
	    *rise* ) echo rise ;;
	    *set*) echo set ;;
	    *road* ) echo road ;;
	    *north* ) echo north ;;
	esac)
    NNTOALL ${h} $f
done

if test -r $1/final.sh ; then
    NNTOALL final $1/final.sh
fi
