/testing/guestbin/swan-prep --x509
ipsec certutil -D -n east
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add main
ipsec whack --impair suppress-retransmits
echo "initdone"
