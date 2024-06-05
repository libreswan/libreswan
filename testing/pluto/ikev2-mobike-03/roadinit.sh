/testing/guestbin/swan-prep
# delete the address 193.1.33.222 before re-run. otherwise pluto may choose it.
../../guestbin/ip.sh address show dev eth0 | grep 192.1.33.222 && ../../guestbin/ip.sh address del 192.1.33.222/24 dev eth0
../../guestbin/ip.sh route show scope global | grep "192.1.33.254" && ip route del default via 192.1.33.254
# add .209 for re-run
../../guestbin/ip.sh address show dev eth0 | grep 192.1.3.209 || ../../guestbin/ip.sh address add 192.1.3.209/24 dev eth0
../../guestbin/ip.sh address add 192.1.33.222/24 dev eth0
# add default gw, it could have been deleted due address changes
../../guestbin/ip.sh route | grep default || ip route add default via 192.1.3.254
# routes and addresses setup for the test
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo "initdone"
