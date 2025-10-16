#!/bin/sh

set -ex

PKI="/usr/libexec/strongswan/pki"
#PKI="/usr/local/strongswan/bin/pki"

x509dir=$(realpath $(dirname $0))
cd ${x509dir}
rm -rf ${x509dir}/strongswan/*
mkdir -p ${x509dir}/strongswan/

pki()
{
    local caname=$1 ; shift
    mkdir ${x509dir}/strongswan/${caname}
    cd ${x509dir}/strongswan/${caname}

    $PKI "$@" > strongCAkey.der
    $PKI "$@" > strongWestKey.der
    $PKI "$@" > strongEastKey.der

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

pki strong-EC --gen --type ecdsa --size 384

#

pki strong-ED --gen --type ed25519
