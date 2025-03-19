#!/bin/sh

conn=west-ku
if test $# -eq 0 ; then
    ku=
    conn=${conn}-missing
else
    ku=$(echo $1 | sed -e s/-/,/)
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
    $(test -n "${ku}" && echo --keyUsage ${ku})

RUN ipsec certutil -L -n ${conn}

RUN ipsec start
/testing/guestbin/wait-until-pluto-started

ipsec whack --impair suppress_retransmits
ipsec whack --impair revival

RUN ipsec whack --name ${conn} \
    --host=192.1.2.45 \
    --id=%fromcert \
    --sendcert=always \
    --cert=${conn} \
    --to \
    --host=192.1.2.23 \
    --id=%any

RUN ipsec up ${conn}

RUN ipsec stop
