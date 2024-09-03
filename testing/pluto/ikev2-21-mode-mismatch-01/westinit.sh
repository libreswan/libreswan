/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.1.2.45 192.1.2.23
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec auto --status | grep ipv4-psk-ikev2-transport
echo "initdone"
ipsec whack --impair revival
