#start ocsp server here
cp -r /testing/x509/keys/nic-nourl.key /etc/ocspd/private/nic_key.pem
cp -r /testing/x509/certs/nic-nourl.crt /etc/ocspd/certs/nic.pem
cp -r /testing/x509/cacerts/mainca.crt /etc/ocspd/certs/mainca.pem
openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
#stock ocspd.conf, used seperate ones for different configs
ocspd -v -d -c /etc/ocspd/ocspd.conf
echo "done."
