/testing/guestbin/swan-prep
ip addr show dev eth0 | grep 192.0.2.250 || (ip addr add 192.0.2.250/24 dev eth0)
ip addr show dev eth0 | grep 192.0.2.251 || (ip addr add 192.0.2.251/24 dev eth0)
ping -c 10000 -I  192.0.2.250  192.0.1.254 2>&1 >/dev/null &
ping -c 10000 -I  192.0.2.251  192.0.1.254 2>&1 >/dev/null & 
ping -c 10000 -I  192.0.2.254  192.0.1.254 2>&1 >/dev/null &
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status
echo "initdone"
