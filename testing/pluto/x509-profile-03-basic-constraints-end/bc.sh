#!/bin/sh

# usage NAME [yn] [critical]

conn=$1 ; shift
bc=n
critical=n

while test $# -gt 0 ; do
    bc=y
    conn=${conn}-${1}
    case ${1} in
	y ) ca=y ;;
	n ) ca=n ;;
	critical ) critical=y ;;
    esac
    shift
done

RUN()
{
    # space is so that sanitize recognizes command
    echo " $@"
    "$@"
}

# generate an end cert, possibly with basic constraints

if test ${bc} = y ; then
    # -2 - basic constraints
    echo ${ca}        # Is this a CA certificate [y/N]?
    echo              # Enter the path length constraint, enter to skip
    echo ${critical}  # Is this a critical extension [y/N]?
fi | {
    RUN ipsec certutil -S \
	-n ${conn} \
	-c mainca \
	-s "E=user-${conn}@testing.libreswan.org,CN=${conn}.testing.libreswan.org,OU=Test Department,O=Libreswan,L=Toronto,ST=Ontario,C=CA" \
	-z $0 \
	-t P,, \
	$(test ${bc} = y && echo -2)
}

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
