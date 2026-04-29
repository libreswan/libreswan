/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12

ipsec start
../../guestbin/wait-until-pluto-started
ipsec add nss-cert-incorrect
ipsec add nss-cert-correct
ipsec whack --impair suppress_retransmits
echo "initdone"
