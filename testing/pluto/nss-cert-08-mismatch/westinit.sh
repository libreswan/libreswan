/testing/guestbin/swan-prep --x509
certutil -D -d sql:/etc/ipsec.d -n road
certutil -D -d sql:/etc/ipsec.d -n east
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add nss-cert-incorrect
ipsec auto --add nss-cert-correct
ipsec whack --impair suppress-retransmits
echo "initdone"
