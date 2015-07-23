#start ocsp server here
setenforce 0
cp -r /testing/x509/keys/nic.key /etc/ocspd/private/nic_key.pem
cp -r /testing/x509/certs/nic.crt /etc/ocspd/certs/nic.pem
cp -r /testing/x509/cacerts/mainca.crt /etc/ocspd/certs/mainca.pem
openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
#stock ocspd.conf, used seperate ones for different configs
ocspd -v -d -c /etc/ocspd/ocspd.conf
echo "done."
