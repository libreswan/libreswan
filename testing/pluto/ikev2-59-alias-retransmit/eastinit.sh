/testing/guestbin/swan-prep
../../guestbin/ip.sh address show dev eth0 | grep 192.0.22.251 || (../../guestbin/ip.sh address add 192.0.22.251/24 dev eth0)
../../guestbin/ip.sh address show dev eth0 | grep 192.0.22.254 || (../../guestbin/ip.sh address add 192.0.22.254/24 dev eth0)
../../guestbin/ip.sh address show dev eth0 | grep 192.0.2.251 || (../../guestbin/ip.sh address add 192.0.2.251/24 dev eth0)
ipsec start
../../guestbin/wait-until-pluto-started
ipsec status | grep north-eastnets
echo "initdone"
