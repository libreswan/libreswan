/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/revoked.p12
/testing/x509/import.sh real/mainca/nic.end.cert
/testing/x509/import.sh real/mainca/crl-is-up-to-date.crl

ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair timeout_on_retransmit
ipsec add nss-cert-crl

echo "initdone"
