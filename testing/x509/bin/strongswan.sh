#!/bin/sh

PKI="/usr/libexec/strongswan/pki"
#PKI="/usr/local/strongswan/bin/pki"

if test $# -lt 2 ; then
    echo "usage: $0 <ca-name> <strongswan-pki-gen-parameters>" 1>&2
    exit 1
fi

if test ! -r description.txt ; then
    echo "$0 should be run from within a test directory" 1>&2
    exit 1
fi

if test ! -d OUTPUT ; then
    echo "OUTPUT/ directory missing" 1>&2
    exit 1
fi

set -ex

x509dir=OUTPUT
rm -rf ${x509dir}/strongswan/*
mkdir -p ${x509dir}/strongswan/

pki()
{
    local caname=$1 ; shift
    mkdir ${x509dir}/strongswan/${caname}
    cd ${x509dir}/strongswan/${caname}

    # no -o option, use dd-of to make dest clear
    :  strongCAkey.der
    $PKI --gen "$@" > strongCAkey.der
    : strongWestKey.der
    $PKI --gen "$@" > strongWestKey.der
    : strongEastKey.der
    $PKI --gen "$@" > strongEastKey.der

    $PKI --self --in strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongSwan ${caname} CA" --ca > strongCAcert.der
    $PKI --pub --in strongWestKey.der | $PKI --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongWest" --flag serverAuth --san west.testing.libreswan.org > strongWestCert.der
    $PKI --pub --in strongEastKey.der | $PKI --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongEast" --flag serverAuth --san east.testing.libreswan.org > strongEastCert.der

    openssl x509 -inform der -outform pem -in strongCAcert.der -out strongCAcert.pem
    openssl x509 -inform der -outform pem -in strongWestCert.der -out strongWestCert.pem
    openssl x509 -inform der -outform pem -in strongEastCert.der -out strongEastCert.pem

    openssl pkey -inform der -outform pem -in strongCAkey.der -out strongCAkey.pem
    openssl pkey -inform der -outform pem -in strongWestKey.der -out strongWestKey.pem
    openssl pkey -inform der -outform pem -in strongEastKey.der -out strongEastKey.pem

    openssl pkcs12 -export -in strongCAcert.pem -inkey strongCAkey.pem -name ${caname} -out strongCAcert.p12 -passout pass:foobar

    openssl pkcs12 -export -in strongWestCert.pem -inkey strongWestKey.pem -certfile strongCAcert.p12 -name strongWest -export -out strongWest.p12 -passout pass:foobar -passcerts pass:foobar
    openssl pkcs12 -export -in strongEastCert.pem -inkey strongEastKey.pem -certfile strongCAcert.p12 -name strongEast -export -out strongEast.p12 -passout pass:foobar -passcerts pass:foobar
}

#

pki "$@"
