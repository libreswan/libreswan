#start ocsp server here
cp -r /testing/x509/keys/nic-nourl.key /etc/ocspd/private/nic_key.pem
cp -r /testing/x509/certs/nic-nourl.crt /etc/ocspd/certs/nic.pem
cp -r /testing/x509/cacerts/mainca.crt /etc/ocspd/certs/mainca.pem
cp /testing/x509/ocspd.conf /etc/ocspd/
openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
#stock ocspd.conf, used separate ones for different configs
restorecon -R /etc/ocspd
ocspd -v -d -c /etc/ocspd/ocspd.conf
echo "done."
: ==== end ====
