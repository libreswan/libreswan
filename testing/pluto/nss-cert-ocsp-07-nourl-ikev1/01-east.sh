/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.all.p12
/testing/x509/import.sh real/mainca/nic.end.cert

# replace nic with the nic-no url cert
ipsec certutil -D -n nic
ipsec certutil -A -i /testing/x509/certs/nic-nourl.crt -n nic -t "P,,"
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec whack --impair timeout_on_retransmit
echo "initdone"
