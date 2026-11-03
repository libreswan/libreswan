#!/bin/sh

# Check all alias entries have an honourable (historic) mention.

configs=$(dirname $0)
top=$(dirname $(realpath ${configs}))

for conf in setup conn ; do
    for a in $(awk -F '"' '/ A\(/ { print $2 }' ${top}/lib/libswan/ipsecconf/${conf}.c | sort) ; do
	echo $a
	if test -f ${configs}/d.ipsec.conf/${conf}/$a.xml ; then
	    echo ${conf} alias $a should not have an entry
	    exit 1
	fi
	if ! grep $a ${configs}/d.ipsec.conf/${conf}/*.xml ; then
	    echo ${conf} alias $a needs an historic mention
	    exit 1
	fi
    done
done
