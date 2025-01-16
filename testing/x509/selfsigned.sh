#!/bin/sh

if test $# -ne 1 ; then
    cat <<EOF
usage: $0 <destdir>
EOF
    exit 1
fi

set -e

DESTDIR=$(realpath $1)

mkdir -p ${DESTDIR}
rm -rf ${DESTDIR}/*
cd ${DESTDIR}

for name in east west north road ; do

    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	    -keyout ${name}-selfsigned.key \
	    -out ${name}-selfsigned.cert \
	    -subj /CN=${name}-selfsigned.testing.libreswan.org \
	    -addext subjectAltName=DNS:${name}.testing.libreswan.org

    openssl pkcs12 -export \
	    -out ${name}-selfsigned.p12 \
	    -inkey ${name}-selfsigned.key \
	    -in ${name}-selfsigned.cert \
	    -certfile ${name}-selfsigned.cert \
	    -passout=file:../nss-pw

done
