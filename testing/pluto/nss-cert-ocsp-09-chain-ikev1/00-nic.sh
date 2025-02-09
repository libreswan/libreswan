#start ocsp server here
cp /testing/x509/keys/nic.key /etc/ocspd/private/nic_key.pem
cp /testing/x509/certs/nic.crt /etc/ocspd/certs/nic.pem
cp /testing/x509/real/mainca/root.cert /etc/ocspd/certs/mainca.pem
cp /testing/x509/ocspd.conf /etc/ocspd/ocspd.conf
openssl crl -inform DER -in /testing/x509/crls/cacrlvalid.crl -outform PEM -out /etc/ocspd/crls/revoked_crl.pem
#stock ocspd.conf, used separate ones for different configs
restorecon -Rv /etc/ocspd
ocspd -v -d -c /etc/ocspd/ocspd.conf
echo "done."
: ==== end ====
