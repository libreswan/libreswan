#!/bin/bash

set -eu

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage:
  $0 <conn> ...

Hack to get around libreswan not defining host-pair search order
during IKE_SA_INIT.  The connections are added such that when multiple
connections match they will be tested per their appearance on the
command line.
EOF
    exit 1
fi

# In 5.0 connections are searched new-to-old.  Hence, need to be added
# in reverse order!

# In 5.1 connections are searched old-to-new.  Hence, can be added in
# order.

connection=( "$@" )
declare -a output
declare -a status

for (( i=$# ; i>0; i--)) ; do
    c=${!i}
    output[$i]=$(ipsec add ${c} 2>&1)
    status[$i]=$?
done

for (( i=1 ; i<=$#; i++)) ; do
    echo "${output[$i]}"
    test "${status[$i]}" -eq 0 || exit "${status[$i]}"
done

exit 0
