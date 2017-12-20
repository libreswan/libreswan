/testing/guestbin/swan-prep
# second address on north 193.1.8.22. nic gw 192.1.8.254
# delete the address 193.1.8.22 before re-run. otherwise pluto may choose it.
ip addr show dev eth1 | grep 192.1.8.22 && ip addr del 192.1.8.22/24 dev eth1
ip route show scope global | grep "192.1.8.254" && ip route del default via 192.1.8.254
# add .33 for re-run
ip addr show dev eth1 | grep 192.1.3.33 || ip addr add 192.1.3.33/24 dev eth1
# add default gw, it could have been deleted due address changes
ip route | grep default || ip route add default via 192.1.3.254
# routes and addresses setup for the test
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
echo "initdone"
