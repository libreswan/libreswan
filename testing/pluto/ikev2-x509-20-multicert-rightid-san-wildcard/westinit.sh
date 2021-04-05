/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add main
ipsec whack --impair suppress-retransmits
echo "initdone"
