/testing/guestbin/swan-prep --nokeys

/testing/x509/import.sh real/mainca/west.all.p12
/testing/x509/import.sh real/mainca/nic.end.cert
/testing/x509/import.sh real/mainca/crl-is-out-of-date.crl

ipsec certutil -L

# need to pass impair into pluto
ipsec pluto --config /etc/ipsec.conf --leak-detective --impair event_check_crls
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival

ipsec add nss-cert-crl
