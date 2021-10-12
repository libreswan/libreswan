# set up the crl server
cp ../../x509/crls/cacrlvalid.crl OUTPUT/revoked.crl
../../guestbin/simple-http-server.sh OUTPUT 80
: ==== end ====
