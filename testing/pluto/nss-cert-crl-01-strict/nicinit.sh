# set up the crl server
cp ../../x509/crls/cacrlvalid.crl OUTPUT/revoked.crl
../bin/simple-http-server.sh OUTPUT 80
: ==== end ====
