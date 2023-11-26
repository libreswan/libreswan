#!/bin/sh -eu

# XXX: Rewrite as utils/fab/kvmhosts.py.

# Assume this script is in testing/utils/ adjacent to
# testing/libvirt/vm.
cd $(dirname $(readlink -f $0))/../libvirt/vm

# Filter out sub-directories (foo/) and temp files (foo.bar) that
# might be lying around.  List all the hosts - don't try to filter out
# "nic".

ls --indicator-style=file-type *.xml | \
    sed -n -e 's/\.xml$//p' | \
    while read h ; do
	case ${h} in
	    e | w )
		for os in netbsd freebsd openbsd debian ; do
		    echo ${os}${h}
		done
		;;
	    * )
		echo ${h}
		;;
	esac
    done
