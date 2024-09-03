/testing/guestbin/swan-prep --nokeys
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add roadnet-eastnet-ipv4-psk-ikev2
ipsec auto --status
echo "initdone"
