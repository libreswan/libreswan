/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ipv4-psk-ikev2-transport
ipsec auto --status | grep ipv4-psk-ikev2-transport
echo "initdone"
