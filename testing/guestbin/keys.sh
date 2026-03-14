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
: Copy the scripts and files /tmp/x509
:

cp /testing/x509/nss-pw		      /tmp/x509

:
: Generate the keys in /tmp/x509
:    - much faster than in /testing
:    - avoids p9fs write bug
:

make -C /testing/x509 X509DIR=/tmp/x509

:
: copy the certs from guest to host in a tar ball to avoid 9fs bug
:

rm -f /testing/x509/kvm-keys.tar
{ cd /tmp/x509 && tar cf kvm-keys.tar */ ; }
cp /tmp/x509/kvm-keys.tar /testing/x509/kvm-keys.tar
