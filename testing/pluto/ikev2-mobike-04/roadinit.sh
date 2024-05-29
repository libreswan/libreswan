/testing/guestbin/swan-prep
# delete the address 192.1.33.209 before re-run. otherwise pluto may choose it.
ip addr show dev eth0 2>/dev/null | grep 192.1.33.209 && ip addr del 192.1.33.209/24 dev eth0
../../guestbin/route.sh show scope global 2>/dev/null | grep "192.1.33.254" && ip route del default via 192.1.33.254
# add 3.209 for re-run
ip addr show dev eth0 | grep 192.1.3.209 || ip addr add 192.1.3.209/24 dev eth0
# add default gw, it could have been deleted due address changes
../../guestbin/route.sh | grep default || ip route add default via 192.1.3.254
# routes and addresses setup for the test
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet
echo "initdone"
