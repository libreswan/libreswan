#!/bin/sh

hostname=$(hostname)

copy_if()
{
    local d=$1 ; shift
    rm -f ${d}
    local s
    for s in "$@" ; do
	test ! -r ${s} && continue
	if test -r ${d} ; then
	    echo "duplicate ${d}: $@" 1>&2
	    exit 1
	fi
	mkdir -p $(dirname ${d})
	cp -v ${s} ${d}
	chmod u=r,go= ${d}
    done
}

log_if() {
    local d=$1
    rm -f /tmp/${d}.log
    if test -r ${2} ; then
	ln -s $PWD/OUTPUT/${hostname}.${d}.log /tmp/${d}.log
    fi
}

#
# Libreswan
#
# install stuff into ${etc}/ipsec.*
#

etc=/usr/local/etc
rm -rf ${etc}/ipsec.d
mkdir ${etc}/ipsec.d

for s in conf secrets ; do
    copy_if ${etc}/ipsec.${s} ${hostname}.${s} ipsec.${s}
done

log_if pluto ${etc}/ipsec.conf

#
# IKED
#
# Install stuff into /etc/*.conf
#

for n in iked.conf ; do
    copy_if /etc/iked.conf ${hostname}.${n} ${n}
done

log_if iked /etc/iked.conf

#
# Racoon
#
# Install stuff into /etc/racoon/*
#

rm -rf /etc/racoon
for p in racoon.conf psk.txt ; do
    copy_if /etc/racoon/${p} ${hostname}.${p} ${p}
done

log_if racoon /etc/racoon/racoon.conf

stty -oxtabs
