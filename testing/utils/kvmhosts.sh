#!/bin/sh -eu

# XXX: Rewrite as utils/fab/kvmhosts.py.

# Assume this script is in testing/utils/ adjacent to
# testing/kvm/vm.
cd $(dirname $(readlink -f $0))/../kvm/vm

# Filter out sub-directories (foo/) and temp files (foo.bar) that
# might be lying around.  List all the hosts - don't try to filter out
# "nic".

ls --indicator-style=file-type *.xml | \
    sed -n -e 's/\.xml$//p' | \
    while read h ; do
	case ${h} in
	    [a-z] )
		for os in alpine debian fedora freebsd netbsd openbsd ; do
		    echo ${os}${h}
		done
		;;
	    * )
		echo ${h}
		;;
	esac
    done
