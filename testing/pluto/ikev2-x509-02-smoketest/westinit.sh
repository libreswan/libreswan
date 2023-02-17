/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
for cert in /testing/x509/pkcs12/mainca/west-*.p12; do ipsec pk12util -i $cert -w /testing/x509/nss-pw; done
ipsec start
../../guestbin/wait-until-pluto-started
# down'ed conn must remain down
ipsec whack --impair revival
echo "initdone"
