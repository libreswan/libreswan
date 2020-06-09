/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add north
ipsec auto --up north
../../pluto/bin/ping-once.sh --up -I 192.0.2.100 192.0.2.254
echo "initdone"
