/testing/guestbin/swan-prep
# we can't test packet flow as we are going to redirect
ip route del 192.0.2.0/24
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ipv4-psk-ikev2
echo "initdone"
