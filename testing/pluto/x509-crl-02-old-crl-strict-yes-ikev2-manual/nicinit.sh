# set up the crl server
cp /testing/x509/real/mainca/crl-is-up-to-date.crl OUTPUT/revoked.crl
../../guestbin/simple-http-server.sh OUTPUT 80
