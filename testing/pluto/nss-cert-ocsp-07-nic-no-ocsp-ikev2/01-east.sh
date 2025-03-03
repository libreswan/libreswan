/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.all.p12
/testing/x509/import.sh real/mainca/nic-no-ocsp.end.cert
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-ocsp
ipsec whack --impair timeout_on_retransmit
echo "initdone"
