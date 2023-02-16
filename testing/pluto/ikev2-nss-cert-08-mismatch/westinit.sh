/testing/guestbin/swan-prep --x509
ipsec certutil -D -n road
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add nss-cert-incorrect
ipsec auto --add nss-cert-correct
ipsec whack --impair suppress-retransmits
echo "initdone"
