/testing/guestbin/swan-prep
ip addr show dev eth0 | grep 192.0.22.251 || (ip addr add 192.0.22.251/24 dev eth0)
ip addr show dev eth0 | grep 192.0.22.254 || (ip addr add 192.0.22.254/24 dev eth0)
ip addr show dev eth0 | grep 192.0.2.251 || (ip addr add 192.0.2.251/24 dev eth0)
ping -f -c 100000 -I  192.0.2.254  192.0.3.254 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.2.251  192.0.3.254 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.22.254  192.0.3.254 2>&1 >/dev/null &
ping -f -c 100000 -I  192.0.22.251  192.0.3.254 2>&1 >/dev/null &
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status | grep north-eastnets
echo "initdone"
