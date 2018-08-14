#!/bin/sh

libreswandir=$(cd $(dirname $(realpath -m $0)); cd ../..; pwd)
cd ${libreswandir}/testing/x509
rm -f strongswan/*
mkdir -p strongswan
cd strongswan
echo "ignore strongswan.conf errors"
strongswan pki --gen --type ecdsa --size 384 > strongCAkey.der
strongswan pki --self --in strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongSwan CA" --ca > strongCAcert.der
strongswan pki --gen --type ecdsa --size 384 > strongWestKey.der
strongswan pki --pub --in strongWestKey.der | strongswan pki --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongWest" --flag serverAuth --san west.testing.libreswan.org > strongWestCert.der
strongswan pki --gen --type ecdsa --size 384 > strongEastKey.der
strongswan pki --pub --in strongEastKey.der | strongswan pki --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongEast" --flag serverAuth --san east.testing.libreswan.org > strongEastCert.der
openssl x509 -inform der -outform pem -in strongCAcert.der -out strongCAcert.pem
openssl x509 -inform der -outform pem -in strongWestCert.der -out strongWestCert.pem
openssl x509 -inform der -outform pem -in strongEastCert.der -out strongEastCert.pem
openssl ec -inform der -outform pem -in strongWestKey.der -out strongWestKey.pem
openssl ec -inform der -outform pem -in strongEastKey.der -out strongEastKey.pem
openssl pkcs12 -export -nodes -in strongWestCert.pem -inkey strongWestKey.pem -certfile strongCAcert.pem -name strongWest -export -out strongWest.p12 -passout pass:foobar
openssl pkcs12 -export -nodes -in strongEastCert.pem -inkey strongEastKey.pem -certfile strongCAcert.pem -name strongEast -export -out strongEast.p12 -passout pass:foobar
