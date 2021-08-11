#!/bin/sh

PKI="/usr/libexec/strongswan/pki"
#PKI="/usr/local/strongswan/bin/pki"

libreswandir=$(cd $(dirname $(realpath -m $0)); cd ../..; pwd)
cd ${libreswandir}/testing/x509
rm -f strongswan/*
mkdir -p strongswan
cd strongswan

$PKI --gen --type ecdsa --size 384 > strongCAkey.der
$PKI --self --in strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongSwan CA" --ca > strongCAcert.der
$PKI --gen --type ecdsa --size 384 > strongWestKey.der
$PKI --pub --in strongWestKey.der | $PKI --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongWest" --flag serverAuth --san west.testing.libreswan.org > strongWestCert.der
$PKI --gen --type ecdsa --size 384 > strongEastKey.der
$PKI --pub --in strongEastKey.der | $PKI --issue --cacert strongCAcert.der --cakey strongCAkey.der --dn "C=CH, O=strongSwan, CN=strongEast" --flag serverAuth --san east.testing.libreswan.org > strongEastCert.der
openssl x509 -inform der -outform pem -in strongCAcert.der -out strongCAcert.pem
openssl x509 -inform der -outform pem -in strongWestCert.der -out strongWestCert.pem
openssl x509 -inform der -outform pem -in strongEastCert.der -out strongEastCert.pem
openssl ec -inform der -outform pem -in strongWestKey.der -out strongWestKey.pem
openssl ec -inform der -outform pem -in strongEastKey.der -out strongEastKey.pem
openssl pkcs12 -export -nodes -in strongWestCert.pem -inkey strongWestKey.pem -certfile strongCAcert.pem -name strongWest -export -out strongWest.p12 -passout pass:foobar
openssl pkcs12 -export -nodes -in strongEastCert.pem -inkey strongEastKey.pem -certfile strongCAcert.pem -name strongEast -export -out strongEast.p12 -passout pass:foobar

$PKI --gen --type ed25519 > strongCAEd25519key.der
$PKI --self --in strongCAEd25519key.der --dn "C=CH, O=strongSwan, CN=strongSwan CA" --ca > strongCAEd25519cert.der
$PKI --gen --type ed25519  > strongWestEd25519Key.der
$PKI --pub --in strongWestEd25519Key.der | $PKI --issue --cacert strongCAEd25519cert.der --cakey strongCAEd25519key.der --dn "C=CH, O=strongSwan, CN=strongWest" --flag serverAuth --san west.testing.libreswan.org > strongWestEd25519Cert.der
$PKI --gen --type ed25519  > strongEastEd25519Key.der
$PKI --pub --in strongEastEd25519Key.der | $PKI --issue --cacert strongCAEd25519cert.der --cakey strongCAEd25519key.der --dn "C=CH, O=strongSwan, CN=strongEast" --flag serverAuth --san east.testing.libreswan.org > strongEastEd25519Cert.der
openssl x509 -inform der -outform pem -in strongCAEd25519cert.der -out strongCAEd25519cert.pem
openssl x509 -inform der -outform pem -in strongWestEd25519Cert.der -out strongWestEd25519Cert.pem
openssl x509 -inform der -outform pem -in strongEastEd25519Cert.der -out strongEastEd25519Cert.pem
openssl pkey -inform der -outform pem -in strongWestEd25519Key.der -out strongWestEd25519Key.pem
openssl pkey -inform der -outform pem -in strongEastEd25519Key.der -out strongEastEd25519Key.pem
openssl pkcs12 -export -nodes -in strongWestEd25519Cert.pem -inkey strongWestEd25519Key.pem -certfile strongCAEd25519cert.pem -name strongWest -export -out strongWestEd25519.p12 -passout pass:foobar
openssl pkcs12 -export -nodes -in strongEastEd25519Cert.pem -inkey strongEastEd25519Key.pem -certfile strongCAEd25519cert.pem -name strongEast -export -out strongEastEd25519.p12 -passout pass:foobar
