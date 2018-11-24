/testing/guestbin/swan-prep
ip route del 192.0.1.0/24
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
