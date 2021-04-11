/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
for cert in /testing/x509/pkcs12/mainca/west-*.p12; do pk12util -i $cert -w /testing/x509/nss-pw -d sql:/etc/ipsec.d; done
ipsec start
../../guestbin/wait-until-pluto-started
# down'ed conn must remain down
ipsec whack --impair revival
echo "initdone"
