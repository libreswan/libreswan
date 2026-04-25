#!/bin/sh

hostname=$(hostname)

# fake cp -v as BSD and Linux print different output

cp_v()
{
    echo "${1} -> ${2}" 1>&2
    cp "${1}" "${2}"
}

# find/copy file, if it exists.

copy_to()
{
    local s="$1" ; shift
    local c="${hostname}.${s} ${s}"
    while test "$#" -gt 1 ; do
	c="${c} $1" ; shift
    done
    local d=$1 ; shift
    if test -d "${d}" ; then
	d="${d}/${s}"
    fi
    local f
    local t=""
    for f in ${c} ; do
	test ! -r "${f}" && continue
	if test -n "${t}" ; then
	    echo "duplicate ${d}: ${t} ${f}" 1>&2
	    exit 1
	fi
	t=${f}
	mkdir -p $(dirname ${d})
	cp_v "${f}" "${d}"
	chmod u=r,go= "${d}"
    done
}

# setup logging for DAEMON when FILE is present

log_if() {
    local daemon=$1
    local file=$2
    rm -f /tmp/${daemon}.log
    if test -r "${file}" ; then
	ln -s $PWD/OUTPUT/${hostname}.${daemon}.log /tmp/${daemon}.log
    fi
}

#
# Libreswan
#
# install stuff into ${etc}/ipsec.*
#

case $(uname) in
    Linux ) etc=/etc ;;
    *BSD ) etc=/usr/local/etc ;;
esac

rm -rf ${etc}/ipsec.d
mkdir ${etc}/ipsec.d

copy_to ipsec.conf    ${hostname}.conf    ${etc}
copy_to ipsec.secrets ${hostname}.secrets ${etc}

log_if pluto ${etc}/ipsec.conf

#
# IKED
#
# Install stuff into /etc/*.conf
#

copy_to iked.conf /etc

log_if iked /etc/iked.conf

#
# Racoon
#
# Install stuff into /etc/racoon/*
#

rm -rf /etc/racoon/*
copy_to racoon.conf /etc/racoon
copy_to psk.txt     /etc/racoon

log_if racoon /etc/racoon/racoon.conf

case $(uname) in
    *BSD ) stty -oxtabs ;;
esac

#
# Strongswan
#

rm -rf /etc/strongswan/*
copy_to strongswan.conf    /etc/strongswan
copy_to swanctl.conf       /etc/strongswan/swanctl
copy_to strongswan.secrets /etc/strongswan/ipsec.secrets

#
# DNS
#

copy_to resolv.conf  /etc
copy_to unbound.conf /etc/unbound

#
# extra stuff
#

while test $# -gt 0 ; do
    case $1 in
	--hostkeys )
	    nssdir=$(ipsec addconn --configsetup=nssdir --config /dev/null)
	    for f in /testing/baseconfigs/$(hostname)/etc/ipsec.d/*.db ; do
		cp_v "${f}" "${nssdir}/$(basename ${f})"
	    done
	    shift
	    ;;
	* )
	    echo "option $1 ignored" 1>&2
	    shift
	    ;;
    esac
done
