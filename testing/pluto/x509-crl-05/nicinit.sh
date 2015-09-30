# set up the crl server
cp /testing/x509/crls/cacrlvalid.crl /testing/pluto/x509-crl-05/revoked.crl
cd /testing/pluto/x509-crl-05
/usr/bin/python -m SimpleHTTPServer 80 &
echo done.
