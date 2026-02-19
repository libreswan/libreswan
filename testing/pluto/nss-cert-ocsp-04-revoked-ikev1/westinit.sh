/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/`hostname`.p12

/testing/x509/import.sh real/mainca/revoked.p12
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair timeout_on_retransmit
ipsec add nss-cert-ocsp
ipsec connectionstatus nss-cert-ocsp
echo "initdone"
