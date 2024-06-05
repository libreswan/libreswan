/testing/guestbin/swan-prep
../../guestbin/ip.sh route
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add roadnet-eastnet-ipv4-psk-ikev2
echo "initdone"
