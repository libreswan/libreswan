/testing/guestbin/swan-prep --x509
certutil -D -n east -d sql:/etc/ipsec.d
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add main
ipsec whack --impair suppress-retransmits
echo "initdone"
