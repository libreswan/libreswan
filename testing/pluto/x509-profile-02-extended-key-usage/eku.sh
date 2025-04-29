#!/bin/sh

conn=west-eku
if test $# -eq 0 ; then
    eku=
    conn=${conn}-missing
else
    eku=$(echo $1 | sed -e s/-/,/)
    conn=${conn}-$1
fi

RUN()
{
    echo " $@"
    "$@"
}

RUN ipsec certutil -S \
    -n ${conn} \
    -c mainca \
    -s "E=user-${conn}@testing.libreswan.org,CN=${conn}.testing.libreswan.org,OU=Test Department,O=Libreswan,L=Toronto,ST=Ontario,C=CA" \
    -z $0 \
    -t P,, \
    --keyUsage digitalSignature \
    $(test -n "${eku}" && echo --extKeyUsage ${eku})

RUN ipsec certutil -L -n ${conn}

RUN ipsec start
/testing/guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits
ipsec whack --impair revival

RUN ipsec addconn --name ${conn} \
    --host=192.1.2.45 \
    --id=%fromcert \
    --sendcert=always \
    --cert=${conn} \
    --to \
    --host=192.1.2.23 \
    --id=%any

RUN ipsec up ${conn}

RUN ipsec stop
