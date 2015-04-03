#!/bin/sh -eu

# XXX: Rewrite as utils/fab/kvmhosts.py.

# Assume this script is in testing/utils/ adjacent to
# testing/libvirt/vm.
cd $(dirname $(readlink -f $0))/../libvirt/vm

# Filter out sub-directories (foo/) and temp files (foo.bar) that
# might be lying around.  List all the hosts - don't try to filter out
# "nic".
ls -F | egrep -e '^[a-z]+$'
