/testing/guestbin/swan-prep
../../guestbin/ip.sh address show dev eth0 | grep 192.0.2.250 || (../../guestbin/ip.sh address add 192.0.2.250/24 dev eth0)
../../guestbin/ip.sh address show dev eth0 | grep 192.0.2.251 || (../../guestbin/ip.sh address add 192.0.2.251/24 dev eth0)
ping -n -q -c 10000 -I  192.0.2.250  192.0.1.254 2>&1 >/dev/null &
ping -n -q -c 10000 -I  192.0.2.251  192.0.1.254 2>&1 >/dev/null & 
ping -n -q -c 10000 -I  192.0.2.254  192.0.1.254 2>&1 >/dev/null &
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status
echo "initdone"
