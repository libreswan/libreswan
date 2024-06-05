/testing/guestbin/swan-prep
../../guestbin/ip.sh address show dev eth0 | grep 192.0.22.251 || (../../guestbin/ip.sh address add 192.0.22.251/24 dev eth0)
../../guestbin/ip.sh address show dev eth0 | grep 192.0.22.254 || (../../guestbin/ip.sh address add 192.0.22.254/24 dev eth0)
../../guestbin/ip.sh address show dev eth0 | grep 192.0.2.251 || (../../guestbin/ip.sh address add 192.0.2.251/24 dev eth0)
ping -n -q -f -c 100000 -I  192.0.2.254  192.0.3.254 2>&1 >/dev/null &
ping -n -q -f -c 100000 -I  192.0.2.251  192.0.3.254 2>&1 >/dev/null &
ping -n -q -f -c 100000 -I  192.0.22.254  192.0.3.254 2>&1 >/dev/null &
ping -n -q -f -c 100000 -I  192.0.22.251  192.0.3.254 2>&1 >/dev/null &
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --status | grep north-eastnets
echo "initdone"
