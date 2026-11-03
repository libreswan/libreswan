#!/bin/sh

# Check all config parameter keywords have documentation.

configs=$(dirname $0)
top=$(dirname $(realpath ${configs}))

for conf in setup conn ; do
    for p in $(awk -F '"' '/ K.*".*K[A-Z]*_/ { print $2 }' ${top}/lib/libswan/ipsecconf/${conf}.c | sort) ; do
	if test ! -f ${top}/configs/d.ipsec.conf/${conf}/$p.xml ; then
	    echo ${conf} parameter $p is not documented
	fi
    done
done
