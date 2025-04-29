#!/bin/sh

set -e

RUN() {
    echo "begin #"
    echo " $@"
    "$@"
    echo "end #"
}

cert=$1
name=$(basename $1)

RUN /testing/x509/import.sh ${cert}.p12
RUN ipsec certutil -L -n ${name}

RUN ipsec start

/testing/guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
RUN ipsec addconn --name ${name} \
    'rightid=C=CA, ST=Ontario, L=Toronto, O=Libreswan, OU=Test Department, CN=east.testing.libreswan.org, E=user-east@testing.libreswan.org' \
    'right=192.1.2.23' \
    'left=%defaultroute' \
    'leftid=%fromcert' \
    'leftcert='${name}

RUN ipsec up ${name} || true

RUN ipsec stop
