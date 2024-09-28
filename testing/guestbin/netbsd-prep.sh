#!/bin/sh

hostname=$(hostname)

#
# Libreswan
#
# install stuff into ${etc}/ipsec.*
#

etc=/usr/local/etc
rm -rf ${etc}/ipsec.d
mkdir ${etc}/ipsec.d

for s in conf secrets ; do
    rm -f ${etc}/ipsec.${s}
    for f in ${hostname}.${s} ipsec.${s} ; do
	if test -r "${f}" ; then
	    cp -v ${f} ${etc}/ipsec.${s}
	fi
    done
done

if test -r ${etc}/ipsec.conf ; then
    rm -f /tmp/pluto.log
    ln -s $PWD/OUTPUT/${hostname}.pluto.log /tmp/pluto.log
fi

#
# Others
#
# install stuff into /etc/*.conf
#

for p in iked ; do
    rm -rf /etc/${p}.conf
    for f in ${hostname}.${p} ${p}.conf ; do
	if test -r "${f}" ; then
	    cp -v ${f} /etc/${p}.conf
	    chmod 600 /etc/${p}.conf
	fi
    done
done

if test -r /etc/iked.conf ; then
    rm -f /tmp/iked.log
    ln -s $PWD/OUTPUT/${hostname}.iked.log /tmp/iked.log
fi

stty -oxtabs
