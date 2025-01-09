#!/bin/sh

set -xe

:
: disable FIPS
:

rm -f /etc/system-fips
/testing/guestbin/fipsoff

:
: Prepare output directory
:

rm -rf /tmp/x509
mkdir /tmp/x509

:
: Copy the scripts to /tmp - need to run in local directory
:

cp /testing/x509/openssl.cnf          /tmp/x509
cp /testing/x509/dist_certs.py	      /tmp/x509
cp /testing/x509/strongswan-ec-gen.sh /tmp/x509

:
: Generate the keys in /tmp/x509
:

{ cd /tmp/x509 && ./dist_certs.py ; }
{ cd /tmp/x509 && ./strongswan-ec-gen.sh ; }

:
: copy the certs from guest to host in a tar ball to avoid 9fs bug
:

rm -f /testing/x509/kvm-keys.tar
{ cd /tmp/x509 && tar cf kvm-keys.tar */ nss-pw ; }
cp /tmp/x509/kvm-keys.tar /testing/x509/kvm-keys.tar
