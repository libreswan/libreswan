# set up the crl server
# in case httpd runs for freeipa tests, shut down httpd
service httpd stop > /dev/null 2> /dev/null
cp /testing/x509/crls/cacrlvalid.crl /testing/pluto/nss-cert-crl-01-strict/revoked.crl
cd /testing/pluto/nss-cert-crl-01-strict
/usr/bin/python -m SimpleHTTPServer 80 &
echo "done."
: ==== end ====
