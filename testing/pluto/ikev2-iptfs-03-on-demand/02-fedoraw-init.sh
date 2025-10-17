/testing/guestbin/swan-prep
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2
ipsec auto --status | grep iptfs
ipsec whack --impair suppress-retransmits
echo "initdone"
