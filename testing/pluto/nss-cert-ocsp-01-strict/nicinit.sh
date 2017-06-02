cp /testing/x509/ocspd.conf /etc/ocspd/ocspd.conf
cp /testing/x509/keys/nic.key /etc/ocspd/private/nic_key.pem
cp /testing/x509/certs/nic.crt /etc/ocspd/certs/nic.pem
cp /testing/x509/cacerts/mainca.crt /etc/ocspd/certs/mainca.pem
openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
restorecon -Rv /etc/ocspd
systemctl start ocspd.service
echo "initdone"
