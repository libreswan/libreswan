#!/bin/sh

etc=/usr/local/etc
rm -rf ${etc}/ipsec.*
mkdir ${etc}/ipsec.d

hostname=$(hostname)

for s in conf secrets ; do
    for f in ${hostname}.${s} ipsec.${s} ; do
	if test -r "${f}" ; then
	    cp -v ${f} ${etc}/ipsec.${s}
	fi
    done
done

rm -f /tmp/pluto.log
ln -s $PWD/OUTPUT/${hostname}.pluto.log /tmp/pluto.log

stty -oxtabs
