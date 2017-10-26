/testing/guestbin/swan-prep --userland strongswan
# delete the address .34 before re-run. otherwise strongswan may choose .34
ip addr show dev eth1 | grep 192.1.3.34 && ip addr del 192.1.3.34/24 dev eth1
# add .33 incase re-run
ip addr show dev eth1 | grep 192.1.3.33 || ip addr add 192.1.3.33/24 dev eth1
# add default gw, it could have been deleted due address changes
ip route | grep default || ip route add default via 192.1.3.254
ip addr add 192.1.3.34/24 dev eth1
../../pluto/bin/strongswan-start.sh
echo "initdone"
