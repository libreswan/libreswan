/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add san
echo "initdone"
