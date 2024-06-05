/testing/guestbin/swan-prep
# second address on north 193.1.8.22. nic gw 192.1.8.254
# delete the address 193.1.8.22 before re-run. otherwise pluto may choose it.
../../guestbin/ip.sh address show dev eth1 | grep 192.1.8.22 && ../../guestbin/ip.sh address del 192.1.8.22/24 dev eth1
../../guestbin/ip.sh route show scope global | grep "192.1.8.254" && ip route del default via 192.1.8.254
# add .33 for re-run
../../guestbin/ip.sh address show dev eth1 | grep 192.1.3.33 || ../../guestbin/ip.sh address add 192.1.3.33/24 dev eth1
../../guestbin/ip.sh address add 192.1.8.22/24 dev eth1
# add default gw, it could have been deleted due address changes
../../guestbin/ip.sh route | grep default || ip route add default via 192.1.3.254
# routes and addresses setup for the test
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
echo "initdone"
