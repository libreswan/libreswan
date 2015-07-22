#!/bin/sh

# generate the key for A
openssl genrsa -out keyA-priv.pem 512

# generate the key for B
openssl genrsa -out keyB-priv.pem 512

# now turn A into self-signed certificate
echo "Generating certificate request."
echo "Please set CN=fakea.libreswan.org and E=fakea@libreswan.org"
openssl req -config ./openssl.cnf -new -key keyA-priv.pem -out keyA.req
openssl x509 -days 3650 -req -signkey keyA-priv.pem -in keyA.req -out keyA.crt

# now turn B into self-signed certificate
echo "Generating certificate request."
echo "Please set CN=fakeb.libreswan.org and E=fakeb@libreswan.org"
openssl req -config ./openssl.cnf -new -key keyB-priv.pem -out keyB.req
openssl x509 -days 3650 -req -signkey keyB-priv.pem -in keyB.req -out keyB.crt

# now sign B's req with A's key.
openssl x509 -days 3650 -CA keyA.crt -CAkey keyA-priv.pem -CAserial fakeindex.txt -req -in keyB.req -out keyAB.crt

# cert certificates to DER format, and concatenate them.
# we keep a uuencoded copy of the concatenation.
openssl asn1parse -inform pem -in keyAB.crt -noout -out keyAB.der
openssl asn1parse -inform pem -in keyB.crt -noout -out keyB.der

cat keyAB.der keyB.der | uuencode keyChain.der >keyChain.duu



