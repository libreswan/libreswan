/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.all.p12
/testing/x509/import.sh real/mainca/nic.end.cert
/testing/x509/import.sh real/mainca/crl-is-up-to-date.crl

ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits

ipsec add nss-cert-crl
