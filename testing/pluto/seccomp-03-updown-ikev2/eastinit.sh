/testing/guestbin/swan-prep
# confirm that the network is alive
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add roadnet-eastnet-ipv4-psk-ikev2
echo "initdone"
