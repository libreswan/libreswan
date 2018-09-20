/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# give time for east to setup
sleep 10
ipsec whack --impair suppress-retransmits
ipsec auto --add north
ipsec auto --up north
ping -n -I 192.0.2.100 -c 4 192.0.2.254
echo "initdone"
